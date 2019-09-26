#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Meta
__version__ = '0.1'
__version_info__ = (0, 1)
__author__ = 'SuicidalLabRat <suicidallabrat@gmail.com>'

import sys
from time import sleep
from getpass import getpass

# Import 3rd party modules
# noinspection PyBroadException
try:
    from paramiko import SSHClient, AutoAddPolicy, ssh_exception
except Exception:
    print(f'ERROR: The Paramiko module is required to use {sys.argv}.')
    print('Download it here: https://github.com/paramiko/paramiko')
    exit(1)

# noinspection PyBroadException
try:
    from scp import SCPClient, SCPException
except Exception:
    print(f'ERROR: The scp module is required to use {sys.argv}.')
    print('Download it here: https://github.com/jbardin/scp.py')
    exit(1)


def root_ssh_access(hname, uname, passwd, rpasswd=None, enable=False, port=22, timeout=15):
    """
    Enable/disable root login to a Nebula meter over ssh.
    If no rpasswd (root password) argument is provided, we assume the youre trying to ssh into the target meter as the
    root user.; this particular mode will only work if the meter is currently configured to allow root ssh login's.
    :param (str) hname: The IP address or hostname of the target meter.
    :param (str) uname: The target meters non-privileged user.
    :param (str) passwd: The password for the target meters non-privileged user.
    :param (str) rpasswd: The password for the target meters root user.
    :param (bool) enable: True: Enable ssh login as root user - False: Disable ssh login as root user.
    :param (int) port: ssh servers listening port.
    :param (int) timeout: ssh client timeout, in seconds.
    :return (bool), (list|None): Returns a bool representing whether the meters root ssh access is in the requested state.
      Further, returns a list containing the lines of the ssh configuration following processing or None if we failed
      to get the meters current ssh configuration.
    """
    comment = ''
    if enable:
        comment = '# '
    dropbear_conf_path = '/etc/default/dropbear'
    dropbear_conf = "# Disallow root logins by default\n"\
                    f"{comment}DROPBEAR_EXTRA_ARGS=\\\"-w\\\"\n"

    # Build an ssh client
    # Uncomment this line to turn on Paramiko debugging (good for troubleshooting where meters report
    # connection failures)
    # paramiko.util.log_to_file('paramiko.log')
    with SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh_client.connect(hname, port, uname, passwd)
        except ssh_exception.AuthenticationException:
            print(f'\n!!! AuthenticationError: Authentication failed logging into {hostname} !!!\n')
            return False, None
        except ssh_exception.NoValidConnectionsError:
            print(f'!!! ConnectionError: Unable to connect to port 22 on {hostname} !!!\n')
            return False, None
        else:
            channel = ssh_client.invoke_shell()

        # If were su'ing to root from a non privileged user to issue our commands...
        if rpasswd:
            channel.send('su -\n')
            while not channel.recv_ready():
                sleep(1)
            output = channel.recv(1024).decode('utf-8')
            channel.send(f'{rpasswd}\n')
            while not channel.recv_ready():
                sleep(1)
            output = channel.recv(1024).decode('utf-8')
            if 'failure' in output:
                print('\n!!!  AuthenticationError: su command failed with authentication error !!!\n')
            else:
                channel.send(f'echo \"{dropbear_conf}\" > {dropbear_conf_path}\n')
                while not channel.recv_ready():
                    sleep(1)
                output = channel.recv(1024).decode('utf-8')

        # If we're ssh'ing in as the root user to issue our command...
        else:
            channel.send(f'echo \"{dropbear_conf}\" > {dropbear_conf_path}\n')
            while not channel.recv_ready():
                sleep(1)
            output = channel.recv(1024).decode('utf-8')
            if 'denied' in output:
                print(f'\n!!! IOError: Permission denied writing to {dropbear_conf_path} !!!\n')

        channel.send(f'cat {dropbear_conf_path}\n')
        while not channel.recv_ready():
            sleep(1)
        current_conf = channel.recv(1024).split(b'\r\n')

        if current_conf:
            # Purge empty list elements and the element storing the 'cat /config/file' command .
            current_conf = list(filter(None, current_conf))
            current_conf.pop(0)
            current_conf.pop()
            if enable:
                if current_conf[-1].decode('utf-8')[0] == comment.strip():
                    return True, current_conf
                else:
                    return False, current_conf
            else:
                if current_conf[-1].decode('utf-8')[0] != '#':
                    return True, current_conf
                else:
                    return False, current_conf

        return False, None


def file_transfer(hname, uname, passwd, local_path, remote_path, put_file=True, port=22):
    """
    Transfer a file to or from a meter.
    :param (str) hname: The IP address or hostname of the target meter.
    :param (str) uname: User account on the target.
    :param (str) passwd: Password for the given target meters user account.
    :param (str) local_path: Path and filename of local file to be transferred to the target meter.
    :param (str) remote_path: Absolute path and filename where the source file will be written on the target meter.
    :param (bool) put_file: If true, send a file to the target meter, otherwise download a file from the target meter.
    :param (int) port: ssh server port, default = 22.
    :return (bool):
    """
    with SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh_client.connect(hname, port, uname, passwd)
        except ssh_exception.AuthenticationException:
            print(f'\n!!! AuthenticationError: Authentication failed logging into {hostname} !!!\n')
            return False
        except ssh_exception.NoValidConnectionsError:
            print(f'!!! ConnectionError: Unable to connect to port 22 on {hostname} !!!\n')
            return False
        else:
            with SCPClient(ssh_client.get_transport()) as scp:
                if put_file:
                    try:
                        scp.put(local_path, remote_path)
                    except SCPException as ex:
                        print(f'\n!!! FileTransferError: Scp exception trying to transfer file !!!\n{ex}')
                        return False
                    except IOError as ex:
                        print(f'\n!!! IOError: Error accessing {local_path} !!!\n{ex}')
                        return True
                    else:
                        return True

                try:
                    scp.get(remote_path)
                except SCPException as ex:
                    print(f'\n!!! FileTransferError: Scp exception trying to get remote file {remote_path} !!!\n{ex}')
                    return False
                except IOError as ex:
                    print(f'\n!!! IOError: Error writing remote file {remote_path} locally !!!\n{ex}')
                    return False
                else:
                    return True


if __name__ == '__main__':
    """
    Testing ...
    """
    # We need to provide some basic info to describe the target meter.
    hostname = '192.168.54.224'
    username = 'redaptive'
    root_username = 'root'

    # Secrets should be captured and temporarily stored by the calling module as apposed to hard coding.
    password = 'xXxXxXxXxXxXx'  # getpass(prompt=f'Enter password for \'{username}\' user: ')  # 'xXxXxXxXxXxXx'  #
    root_password = 'test'  # getpass(prompt=f'Enter password for the \"{root_username}\" user: ')  # 'test'  #

    # (ssh_result, resulting_config) = root_ssh_access(hostname, username, password, root_password, True)
    # print(f'Return Status: {ssh_result}')
    # if resulting_config:
    #     print('Current root login setting in ssh config file:  {0}\n'.format(resulting_config[-1].decode('utf-8')))

    # scp_result = file_transfer(hostname, root_username, root_password, 'test_scp_file.txt', '/tmp/test.txt')
    # if scp_result:
    #     print(f'File transfer result: {scp_result}')



    # Until we are done interacting with the meters, lets keep the app running and the credentials stored locally.
    # try:
    #     while True:
    #         ssh.connect(hostname, 22, username, password)
    #         # Example enabling root ssh access on a given meter.
    #         print(f'Unocking ssh on {hostname}...')
    #         (ssh_result, resulting_config) = root_ssh_access(ssh, root_password, True)
    #
    #         # The return values include a boolean representing whether the target meters root ssh access is currently
    #         # in the requested state, and a list containing the lines of the current ssh config file.
    #         print(f'Return Status: {ssh_result}')
    #         print('Current root login setting in ssh config file:  {0}\n'.format(resulting_config[-1].decode('utf-8')))
    #
    #         # Send files and run remote commands
    #         if '#' not in resulting_config[-1].decode('utf-8'):
    #             # Configure our ssh client to use the root user and password.
    #             ssh.connect(hostname, 22, root_username, root_password)
    #
    #             try:
    #                 scp_result = file_transfer(ssh, 'test_scp_file.txt', '/tmp/testFile.txt')
    #                 print(f'scp result: {scp_result}')
    #             except Exception as e:
    #                 print(f'There was an exception while sending files!\n{e}')
    #             else:
    #                 print(f'Locking down ssh on {hostname}...')
    #                 (ssh_result, resulting_config) = root_ssh_access(ssh, root_password)
    #                 print(f'Return Status: {ssh_result}')
    #                 print('Current root login setting in ssh config file:  {0}\n'.format(resulting_config[-1].decode('utf-8')))
    #             finally:
    #                 resp = input('\nDo you want to process another meter? [y|n]: ')
    #                 if resp != 'y':
    #                     print('Exiting...')
    #                     sys.exit(0)
    #
    # except KeyboardInterrupt:
    #     print('Exiting...')
    #     sys.exit(0)
