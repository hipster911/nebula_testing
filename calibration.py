#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Meta
__version__ = '0.1'
__version_info__ = (0, 1)
__author__ = 'SuicidalLabRat <suicidallabrat@gmail.com>'
import sys
from remote_control import root_ssh_access, file_transfer
from gooey import Gooey
from gooey import GooeyParser
from colored import stylize, attr, fg


@Gooey(dump_build_config=True, program_name='Calibration Deployer', richtext_controls=True, auto_start=True)
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
    password = args.password
    root_password = args.root_password
    local_file_path = args.local_file_path
    remote_file_path = '/data/'

    exit_code = 0

    while True:
        print("\n" * 20)
        # Enabling root ssh access on a given meter.
        print(stylize(f'Unlocking ssh on {hostname}...', attr('bold')))
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

        sys.exit(exit_code)


if __name__ == '__main__':
    main()
