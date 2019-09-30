#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Meta
__version__ = '0.1'
__version_info__ = (0, 1)
__author__ = 'SuicidalLabRat <suicidallabrat@gmail.com>'
import sys
from os import path
from time import sleep
from io import StringIO
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
            print(f'!!! AuthenticationError: Authentication failed logging into {hname} !!!\n')
            return False, None
        except ssh_exception.NoValidConnectionsError:
            print(f'!!! ConnectionError: Unable to connect to port 22 on {hname} !!!')
            return False, None
        except TimeoutError:
            print(f'!!! Timed out trying to connect to {hname} !!!')
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
                print('!!! AuthenticationError: su command failed with authentication error !!!')
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
                print(f'!!! IOError: Permission denied writing to {dropbear_conf_path} !!!')

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


def file_transfer(hname, uname, passwd, file_paths,  put_file=True, port=22):
    """
    Transfer a file to or from a meter.
    :param (str) hname: The IP address or hostname of the target meter.
    :param (str) uname: User account on the target.
    :param (str) passwd: Password for the given target meters user account.
    :param (list) file_paths: List of tuples containing source filename, including path, as a string OR file-like-object
     and the destination filename, including path, as a strings.
    :param (bool) put_file: If true, send a file to the target meter, otherwise download a file from the target meter.
    :param (int) port: ssh server port, default = 22.
    :return (bool, list): Returns true if all file transfers are successful, otherwise false.  Also returns a list of
    key: bool, value: tuple, where tuple is the src and dst files and the key represents the success/failure of that
    particular file transfer.
    """
    with SSHClient() as ssh_client:
        ssh_client.set_missing_host_key_policy(AutoAddPolicy())
        try:
            ssh_client.connect(hname, port, uname, passwd)
        except ssh_exception.AuthenticationException:
            print(f'!!! AuthenticationError: Authentication failed logging into {hname} !!!\n')
            return False
        except ssh_exception.NoValidConnectionsError:
            print(f'!!! ConnectionError: Unable to connect to port 22 on {hname} !!!\n')
            return False
        else:
            return_status = True
            status_list = []
            with SCPClient(ssh_client.get_transport()) as scp:

                if put_file:
                    for src, dst in file_paths:
                        if not isinstance(src, StringIO) and not path.isfile(src):
                            print(f'!!! IOError: Error accessing {src} !!!\n')
                            status_list.append((False, (src, dst)))
                            return_status = False
                            continue
                        try:
                            if not isinstance(src, StringIO):
                                scp.put(src, dst)
                            else:
                                print(f'src is a file-like-object!')
                                scp.putfo(src, dst)

                        except SCPException:
                            print(f'!!! FileTransferError: Scp exception trying to transfer file {src} -> {dst} !!!\n')
                            status_list.append((False, (src, dst)))
                            return_status = False
                        except IOError:
                            print(f'!!! IOError: Error accessing {src} !!!\n')
                            status_list.append((False, (src, dst)))
                            return_status = False
                        except ssh_exception.SSHException:
                            print('ssh exception!')

                        else:
                            status_list.append((True, (src, dst)))

                    return return_status, status_list

                for src, dst in file_paths:
                    try:
                        scp.get(dst)
                    except SCPException:
                        print(f'!!! FileTransferError: Scp exception trying to get remote file {dst} !!!\n')
                        status_list.append((False, (src, dst)))
                        return_status = False
                    except IOError:
                        print(f'!!! IOError: Error writing remote file {dst} locally !!!\n')
                        status_list.append((False, (src, dst)))
                        return_status = False
                    else:
                        status_list.append((True, (src, dst)))

                return return_status, status_list


def main():
    """
    Usage example...
    """
    # We need to provide some basic info to describe the target meter.
    hostname = '192.168.0.186'
    username = 'redaptive'
    root_username = 'root'
    password = getpass(prompt=f'Enter password for the \'{username}\' user: ')
    root_password = getpass(prompt=f'Enter password for the \"{root_username}\" user: ')
    cal_file_src = '../meterCalData.json'
    cal_file_dst = '/data/'
    config_file_src = '../meterConfigData.json'
    config_file_dst = '/data/'
    fl_name = '/data/fileLikeObject.txt'

    # generate in-memory file-like object for testing.
    fl = StringIO()
    fl.write('This is supposed to be a file file object!\n\r')
    fl.seek(0)

    file_list = [
        (cal_file_src, cal_file_dst),
        (config_file_src, config_file_dst),
        (fl, fl_name)
    ]

    # Example enabling root ssh access on a given meter.
    # Note: Returns a bool representing whether the meters root ssh access is in the requested state.
    #       Further, returns a list containing the lines of the ssh configuration following processing or None if we
    #       failed to get the meters current ssh configuration.
    (ssh_result, resulting_config) = root_ssh_access(hostname, username, password, root_password, True)

    if ssh_result:
        # Transfer a file to a remote meter - assumes root ssh access has been enabled on the remote meter.
        scp_result, return_list = file_transfer(hostname, root_username, root_password, file_list)
        print(f'Status: {scp_result}\nStatus list:\n{return_list}')

    # Example disabling root ssh access on a given meter.
    (ssh_result, resulting_config) = root_ssh_access(hostname, username, password, root_password)


if __name__ == '__main__':
    main()
