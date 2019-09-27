#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Meta
__version__ = '0.1'
__version_info__ = (0, 1)
__author__ = 'SuicidalLabRat <suicidallabrat@gmail.com>'
from gooey import Gooey
from gooey import GooeyParser
from colored import stylize, attr, fg
import sys
from time import sleep
# from getpass import getpass

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
            print(f'!!! AuthenticationError: Authentication failed logging into {hname} !!!\n')
            return False
        except ssh_exception.NoValidConnectionsError:
            print(f'!!! ConnectionError: Unable to connect to port 22 on {hname} !!!\n')
            return False
        else:
            with SCPClient(ssh_client.get_transport()) as scp:
                if put_file:
                    try:
                        scp.put(local_path, remote_path)
                    except SCPException as ex:
                        print(f'!!! FileTransferError: Scp exception trying to transfer file !!!{ex}\n')
                        return False
                    except IOError as ex:
                        print(f'!!! IOError: Error accessing {local_path} !!!')
                        return False
                    else:
                        return True

                try:
                    scp.get(remote_path)
                except SCPException as ex:
                    print(f'!!! FileTransferError: Scp exception trying to get remote file {remote_path} !!!{ex}\n')
                    return False
                except IOError as ex:
                    print(f'!!! IOError: Error writing remote file {remote_path} locally !!!{ex}\n')
                    return False
                else:
                    return True


@Gooey(dump_build_config=True, program_name='Calibration Deployer', richtext_controls=True, auto_start=True)  # image_dir='/path/to/my/image/directory')
def main():
    """
    Testing ...
    """
    desc = 'Calibration Deployment Tool'

    parser = GooeyParser(description=desc)
    parser.add_argument(
        'password',
        metavar='Redaptive Password',
        help='Password for redaptive user',
        widget='PasswordField')
    parser.add_argument(
        'root_password',
        metavar='Root Password',
        help='Password for root user',
        widget='PasswordField')
    parser.add_argument(
        'local_file_path',
        metavar='Calibration File',
        # required=True,
        default='meterCalData.json',
        help='File to be deployed',
        widget='FileChooser')
    parser.add_argument(
        'hostname',
        metavar='Target Meter',
        default='192.168.54.224',
        help='Meter hostname or IP address')

    args = parser.parse_args()

    # We need to provide some basic info to describe the target meter.
    hostname = args.hostname
    username = 'redaptive'
    root_username = 'root'
    password = args.password  # getpass(prompt=f'Enter password for the \'{username}\' user: ')  # 'xXxXxXxXxXxXx'
    root_password = args.root_password  # getpass(prompt=f'Enter password for the \"{root_username}\" user: ')
    local_file_path = args.local_file_path
    remote_file_path = '/data/'

    exit_code = 0
    # Until we are done interacting with the meters, lets keep the app running and the credentials stored locally.
    try:
        while True:
            # Example enabling root ssh access on a given meter.
            print(stylize(f'Unlocking ssh on {hostname}...', attr('bold')))  # .format(hostname))
            (ssh_result, resulting_config) = root_ssh_access(hostname, username, password, root_password, True)

            if ssh_result:
                current_config = resulting_config[-1].decode('utf-8')
                print(stylize(f'Unlocked root ssh\n'
                              f'Current configuration = {current_config}\n', fg('green')))

                print(stylize(f'Transferring file(s) to meter @{hostname}', attr('bold')))
                scp_result = file_transfer(hostname, root_username, root_password, local_file_path, remote_file_path)

                if scp_result:
                    print(stylize('File transfer succeeded!\n', fg("green")))
                else:
                    print(stylize('File transfer failed.\n', fg("red"), attr('bold')))
                    exit_code = 1
            else:
                print(stylize(f'Failed to unlock {hostname}.\n', fg("red")))
                exit_code = 1
            print(stylize(f'Running fail-safe attempt to lock down ssh on {hostname}...', attr('bold')))
            (ssh_result, resulting_config) = root_ssh_access(hostname, root_username, root_password)

            if ssh_result:
                current_config = resulting_config[-1].decode('utf-8')
                print(stylize(f'Successfully locked down ssh access on {hostname}\n'
                              f'Current configuration = {current_config}\n', fg('green')))
            else:
                print(stylize(f'Failed to lock down ssh access on {hostname}!\n', fg('red'), attr('bold')))
                exit_code = 1
                if resulting_config:
                    current_config = resulting_config[-1].decode('utf-8')
                    print(f'The current ssh config includes the following root login line:\n{current_config}')
                print(stylize('You may want to try re-running the enable/disable process again.', fg("yellow")))

            # resp = input('\nDo you want to process another meter? [y|n]: ')
            # if resp != 'y':
            #     print('Exiting...')
            sys.exit(exit_code)

    except KeyboardInterrupt:
        print('Exiting...')
        sys.exit(exit_code)


if __name__ == '__main__':
    main()
