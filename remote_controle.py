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


def root_ssh_access(ssh_client, rpasswd=None, enable=False):  # (hname, uname, passwd, rpasswd, enable=False):
    """
    Enable/disable remote ssh access to a Nebula meter as the root user.
    If no rpasswd (root password) argument is provided, we assume the ssh_client
    is configured as the root user for the target meter; this particular
    mode will only work if the meter is currently configured to allow ssh login's
    as user root.
    :param (obj) ssh_client: Paramiko SSHClient object.
    :param (str) rpasswd: The password for the target meters root user.
    :param (bool) enable: True: Enable ssh login as root user - False: Disable ssh login as root user.
    :return (bool), (list): Returns a bool representing whether the meters root ssh access is in the requested state.
      Further, returns a list containing the lines of the ssh configuration following processing.
    """
    comment = ''
    if enable:
        comment = '# '
    dropbear_conf_path = '/etc/default/dropbear'
    dropbear_conf = "# Disallow root logins by default\n"\
                    f"{comment}DROPBEAR_EXTRA_ARGS=\\\"-w\\\"\n"
    channel = ssh_client.invoke_shell()

    try:
        if rpasswd:
            channel.send('su -\n')
            while not channel.recv_ready():
                sleep(1)
            print(channel.recv(1024).decode('utf-8'))
            channel.send(f'{rpasswd}\n')
            while not channel.recv_ready():
                sleep(1)
            output = channel.recv(1024).decode('utf-8')
            if 'failure' in output:
                print('\n!!! su command failed with authentication error !!!\n')
            else:
                channel.send(f'echo \"{dropbear_conf}\" > {dropbear_conf_path}\n')
                while not channel.recv_ready():
                    sleep(1)
                print(channel.recv(1024).decode('utf-8'))
        else:
            channel.send(f'echo \"{dropbear_conf}\" > {dropbear_conf_path}\n')
            while not channel.recv_ready():
                sleep(1)
            print(channel.recv(1024).decode('utf-8'))
        channel.send(f'cat {dropbear_conf_path}\n')
        while not channel.recv_ready():
            sleep(1)
        current_conf = channel.recv(1024).split(b'\r\n')
    except ssh_exception.AuthenticationException as e:
        print(f'Authentication failed logging into {e}.\n')
    except ssh_exception.NoValidConnectionsError:
        print(f'Unable to connect to port 22 on target meter.')
        return False, None
    except Exception:
        raise
    else:
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


def file_transfer(ssh_client, local_path, remote_path, put_file=True):
    with SCPClient(ssh_client.get_transport()) as scp:
        if put_file:
            try:
                scp.put(local_path, remote_path)
            except SCPException:
                print(f'Scp exception trying to transfer file!')
                raise
            except IOError:
                print(f'IO error accessing {local_path}.')
                raise
            except Exception:
                raise
            else:
                return True

        try:
            scp.get(remote_path)
        except SCPException:
            print(f'Scp exception trying to get remote file {remote_path}!')
            raise
        except IOError:
            print(f'IO error writing remote file {remote_path} locally.')
            raise
        except Exception:
            raise
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

    # Build an ssh client
    ssh = SSHClient()
    ssh.set_missing_host_key_policy(AutoAddPolicy())
    try:
        ssh.connect(hostname, 22, username, password)
    except ssh_exception.AuthenticationException:
        print(f'Authentication failed logging into {hostname}.\n')


    (ssh_result, resulting_config) = root_ssh_access(ssh, root_password, True)

    # The return values include a boolean representing whether the target meters root ssh access is currently
    # in the requested state, and a list containing the lines of the current ssh config file.
    # print(f'Return Status: {ssh_result}')
    # print('Current root login setting in ssh config file:  {0}\n'.format(resulting_config[-1].decode('utf-8')))
    #
    # if ssh_result:  # This should actually be a test of whether the meter is config'ed to allow root ssh.
    #     ssh.connect(hostname, 22, root_username, root_password)
    #     scp_result = file_transfer(ssh, 'test_scp_file.txt', '/tmp/testFile.txt')
    #     print(f'scp result: {scp_result}')

    # Until we are done interacting with the meters, lets keep the app running and the credentials stored locally.
    try:
        while True:
            ssh.connect(hostname, 22, username, password)
            # Example enabling root ssh access on a given meter.
            print(f'Unocking ssh on {hostname}...')
            (ssh_result, resulting_config) = root_ssh_access(ssh, root_password, True)

            # The return values include a boolean representing whether the target meters root ssh access is currently
            # in the requested state, and a list containing the lines of the current ssh config file.
            print(f'Return Status: {ssh_result}')
            print('Current root login setting in ssh config file:  {0}\n'.format(resulting_config[-1].decode('utf-8')))

            # Send files and run remote commands
            if '#' not in resulting_config[-1].decode('utf-8'):
                # Configure our ssh client to use the root user and password.
                ssh.connect(hostname, 22, root_username, root_password)

                try:
                    scp_result = file_transfer(ssh, 'test_scp_file.txt', '/tmp/testFile.txt')
                    print(f'scp result: {scp_result}')
                except Exception as e:
                    print(f'There was an exception while sending files!\n{e}')
                else:
                    print(f'Locking down ssh on {hostname}...')
                    (ssh_result, resulting_config) = root_ssh_access(ssh, root_password)
                    print(f'Return Status: {ssh_result}')
                    print('Current root login setting in ssh config file:  {0}\n'.format(resulting_config[-1].decode('utf-8')))
                finally:
                    resp = input('\nDo you want to process another meter? [y|n]: ')
                    if resp != 'y':
                        print('Exiting...')
                        sys.exit(0)

    except KeyboardInterrupt:
        print('Exiting...')
        sys.exit(0)
