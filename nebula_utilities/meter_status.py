import importlib.util
from collections import namedtuple
from datetime import datetime
from collections.abc import Mapping
import os
from sys import stdout as sys_stdout
import re
import uuid
import subprocess
import socket
import fcntl
import struct
import hashlib
from platform import release as kernel_release
from json import dumps
from json import load
import pathlib
import csv


def read_run_file(name, path='/run/'):
    try:
        with open(f'{path}{name}', 'r') as f:
            json_data = load(f)
    except Exception as e:
        pass
    else:
        return json_data

    try:
        with open(f'{path}{name}', 'r') as f:
            version_string = f.readline()
    except Exception as e:
        print(e)
        return None
    else:
        return version_string


def get_software_version(name):
    if re.search(r'meter(.*)app', name, flags=re.IGNORECASE):
        return read_run_file('meter_app_version').strip()
    elif re.search(r'rd(.*)accum', name, flags=re.IGNORECASE):
        v = run_cmd(['RD_Accum', '-v'])
        if v:
            return v[0].split()[7].decode().strip()
        else: return None
    elif name.lower() == 'stm32':
        return read_run_file('stm32_version').strip()
    elif re.search(r'ims2(.*)cmd(.*)', name, flags=re.IGNORECASE):
        non_std_mod_path = '/usr/bin/ims2_cmd_interface.py'
        modules = import_python_modules_by_path(non_std_mod_path)
        if modules:
            return modules[0].__version__
        return None
    elif re.search(r'mender(.*)', name, flags=re.IGNORECASE):
        v = run_cmd(['mender', '-version'])
        if v:
            arr = v[0].strip().split()

            return arr[len(arr) - 3].decode().strip()
        else:
            return None


def get_software_checksum(file, algorithm='MD5'):
    """
    Calculates the checksum of (a path to) a file, with the provided algorithm.
    :param file: The input file for which a hash will be generated.
    :param algorithm: Hashing algorithm - MD5|SHA-1|SHA-224|SHA-256|SHA-384|SHA-256.
    :return: Tuple: [0]calculated checksum [1]algorithm used [2]file calculation is based on. [3]size of file (in bytes).
    """
    if algorithm == "MD5":
        hash_func = hashlib.md5()
    elif algorithm == "SHA-1":
        hash_func = hashlib.sha1()
    elif algorithm == "SHA-224":
        hash_func = hashlib.sha224()
    elif algorithm == "SHA-256":
        hash_func = hashlib.sha256()
    elif algorithm == "SHA-384":
        hash_func = hashlib.sha384()
    elif algorithm == "SHA-512":
        hash_func = hashlib.sha512()
    else:
        print("Error: " + algorithm + " is an unknown algorithm!\n")
        return None, None

    # Read the file (in chunks; to prevent choking the RAM when reading large files).
    try:
        with open(file, "rb") as f:
            while True:
                file_data = f.read(8192)  # Block size = 8192 Bytes (8 KB)
                if not file_data:
                    break
                hash_func.update(file_data)
    except Exception as e:
        print('Error calculating checksum for file {0}!\n{1}'.format(file, e))
        return None, None
    else:
        return hash_func.hexdigest(), \
               algorithm, \
               file, \
               os.path.getsize(file)


def get_eeprom_data():
    from sys import _getframe
    my_name = _getframe().f_code.co_name
    hardware_id = {}

    # If it exists, use the smbus module to read the EEPROM programmatically,
    # otherwise make shell calls to the i2ctools to achieve the same
    try:
        from smbus2 import SMBus
    except ModuleNotFoundError:
        print('{0}: smbus module not available for import, will attempt to read eeprom from cmdline...'.format(my_name))
    else:
        byte_count = 0
        address = 0x50
        bus = smbus.SMBus(0)
        bus.write_byte_data(address, 0x20, 0x20)  # the 0x20, 0x20 is the '16 bit' address split into 2 bytes
        while byte_count <= 3:
            try:
                result = bus.read_byte(address)  # reads at the current address pointer, which we set on the previous line
            except Exception as e:
                print('Error getting hardware id from eeprom.')
                return None
            else:
                byte_count += 1
                if byte_count == 1:
                    hardware_id['model'] = result
                elif byte_count == 2:
                    if hardware_id['model'] != '00':
                        hardware_id['hsm'] = result
                    else:
                        hardware_id['hsm'] = None
                        hardware_id['version'] = result
                elif byte_count == 3:
                    hardware_id['version'] = result

        return hardware_id

    # Try using i2ctools from the shell.
    i2cset = '/usr/sbin/i2cset'
    i2cget = '/usr/sbin/i2cget'
    try:
        set_i2c_pointer = subprocess.run([i2cset, '-y', '0', '0x50', '0x20', '0x20'])
        if set_i2c_pointer.returncode != 0:
            print('{0}: i2cset exited on non 0 return code. [{1}]'.format(my_name, set_i2c_pointer.returncode))
            return None
    except Exception as ex:
        print('{0}: Failed to run \'i2cset\' system command to get eeprom data. - {1}'.format(my_name, ex))
        return None
    else:
        # GET FIRST BYTE
        try:
            eeprom_byte = subprocess.run([i2cget, '-y', '0', '0x50'], stdout=subprocess.PIPE)
            if eeprom_byte.returncode != 0:
                print('{0}: i2cset exited on non 0 return code. [{1}]'.format(my_name, set_i2c_pointer.returncode))
                return None
        except Exception as ex:
            print('{0}: Failed to run \'i2cget\' system command to get the first byte of our eeprom data. - {1}'
                  .format(my_name, ex))
            return None
        else:
            hardware_id['model'] = eeprom_byte.stdout[2:].decode().rstrip('\n')

        # GET SECOND BYTE
        try:
            eeprom_byte = subprocess.run([i2cget, '-y', '0', '0x50'], stdout=subprocess.PIPE)
            if eeprom_byte.returncode != 0:
                print('{0}: i2cset exited on non 0 return code. [{1}]'.format(my_name, set_i2c_pointer.returncode))
                return None
        except Exception as ex:
            print('{0}: Failed to run \'i2cget\' system command to get the second byte of our eeprom data. - {1}'
                  .format(my_name, ex))
            return None
        else:
            # Big Bang meters only use 2 bytes, where the second byte is the hardware version. Nebula uses the second
            # byte to identify the HSM security mode, and the third byte as the hardware ID.
            if hardware_id['model'] != '00':
                hardware_id['hsm'] = eeprom_byte.stdout[2:].decode().rstrip('\n')
            else:
                hardware_id['hsm'] = None
                hardware_id['version'] = eeprom_byte.stdout[2:].decode().rstrip('\n')
                return hardware_id

        # GET THIRD BYTE
        try:
            eeprom_byte = subprocess.run([i2cget, '-y', '0', '0x50'], stdout=subprocess.PIPE)
            if eeprom_byte.returncode != 0:
                print('{0}: i2cset exited on non 0 return code. [{1}]'.format(my_name, set_i2c_pointer.returncode))
                return None
        except Exception as ex:
            print('{0}: Failed to run \'i2cget\' system command to get the third byte of our eeprom data. - {1}'
                  .format(my_name, ex))
            return None
        else:
            hardware_id['version'] = eeprom_byte.stdout[2:].decode().rstrip('\n')

        return hardware_id


def get_running_processes():
    processes = []
    pids = [pid for pid in os.listdir('/proc') if pid.isdigit()]
    for pid in pids:
        try:
            process = open(os.path.join('/proc', pid, 'cmdline'), 'r').read().split('\0')
        except IOError:
            print('Process ID {} is no longer there, maybe it has already terminated.'.format(pid))
            continue
        except Exception:
            return None
        else:
            if not '' in process[:1]:
                process.insert(0, pid)
                processes.append(process)
    if processes:
        return processes


def get_process_info(proc_name):
    """
    Returns tuple with the process ID and the path/filename of the process executable.
    If there are multiple instances of the given process name, only the first is returned.
    """
    processes = get_running_processes()
    if processes:
        for process in processes:
            pid = process[0]
            path_index = [n for n, x in enumerate(process) if proc_name in x]
            if path_index:
                return pid, process[path_index[0]]  # If there are multiple instances, only return the first.
    return None, None


def run_cmd(*args, **kwargs):
    try:
        process = subprocess.Popen(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    except Exception as e:
        print(e)
        return None
    else:
        return process.communicate()  # returns (stdout, stderr)


def list_files(base_path, ext=None):
    files = []
    try:
        for entry in os.listdir(base_path):
            if os.path.isfile(os.path.join(base_path, entry)):
                _, entry_ext = os.path.splitext(entry)
                entry_ext = entry_ext.lstrip('.')

                if (ext is None) or \
                        (isinstance(ext, str) and entry_ext == ext) or \
                        (isinstance(ext, list) and entry_ext in ext):
                    files.append(entry)
    except IOError as e:
        print("Path does not exist: {0}\n{1}".format(base_path, e))
        return None
    except Exception as e:
        print(e)
        return None
    else:
        return files


def extract_filename(path):
    try:
        filename = list(os.path.splitext(os.path.basename(path)))[0]
    except Exception as e:
        print(e)
        return None
    else:
        return filename


def import_python_modules_by_path(path):
    """ We need to import some Redaptive python modules so that we can get their version information,
        but they are in nonstandard python module locations.
    """
    imported_modules = []
    if os.path.isfile(path):
        file_list = [path]
    else:
        file_list = list_files(path, "py")

    if file_list:
        for filename in file_list:
            try:
                name = extract_filename(filename)
                spec = importlib.util.spec_from_file_location(name, os.path.join(path, filename))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
            except Exception as e:
                print('Failed to load module {0}.\n{1}'.format(filename, e))
                continue
            else:
                imported_modules.append(module)
        return imported_modules
    return None


def get_kernel_version():
    try:
        return kernel_release()
    except Exception:
        return None


def get_uboot_version():
    try:
        version = subprocess.check_output('/sbin/fw_printenv | grep ver=U', shell=True).strip().decode()
        return version.split('=')[1]
    except Exception as e:
        # print('Failed to get uboot version string.\n{}'.format(e))
        return None


def get_hostname():
    try:
        return socket.gethostname()
    except Exception:
        print('Failed to get hostname.')
        return None


def get_system_time():
    try:
        return datetime.strptime(datetime.now().strftime('%Y-%m-%d %H:%M:%S'), '%Y-%m-%d %H:%M:%S')
    except Exception:
        print('Failed to get system time.')
        return None


def get_uptime(fancy = False):
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
    except Exception:
        print('failed to get system uptime')
        return None
    else:
        if fancy:
            return normalize_seconds(round(uptime_seconds))
        return uptime_seconds


def normalize_seconds(seconds: int) -> tuple or None:
    try:
        (days, remainder) = divmod(seconds, 86400)
        (hours, remainder) = divmod(remainder, 3600)
        (minutes, seconds) = divmod(remainder, 60)
    except Exception as e:
        print('Failed to convert seconds to d:h:m:s.\n{}'.format(e))
        return None
    else:
        return namedtuple("_", ("days", "hours", "minutes", "seconds"))(days, hours, minutes, seconds)


def get_load_average(sample_time=15):
    st = {1: 0, 5: 1, 15: 2, 'default': 2}.get(sample_time)
    try:
        with open('/proc/loadavg', 'r') as f:
            load_avg = float(f.readline().split()[st])
    except Exception:
        print('Failed to get system load average.')
        return None
    else:
        return load_avg


def get_os_version():
    try:
        with open('/etc/issue', 'r') as f:
            os_version = f.read()
    except Exception:
        print('Failed to get OS version string.')
        return None
    else:
        return os_version.replace('\n', "")


def get_signal_str(path='/var/spool/redaptive'):
    file_list = list_files(path, 'ss')
    try:
        latest = sorted(file_list).pop()
        with open(os.path.join(path, latest), 'r') as f:
            s_str = f.readline().split(',')
    except Exception as e:
        # print(e)
        return None
    else:
        return s_str


def get_radio_metadata(filename):
    try:
        return read_run_file(filename)
    except Exception:
        return None


def get_mac():
    try:
        return ''.join(re.findall('..', '%012x' % uuid.getnode()))
    except Exception:
        print('Failed to get system MAC address.')
        return None


def get_ip_address(ifname='eth0'):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0")  # Bind a particular interface.
    try:
        ip_addr = socket.inet_ntoa(fcntl.ioctl(
            s.fileno(), 0x8915,  # SIOCGIFADDR
            struct.pack('256s', ifname.encode()[:15])
        )[20:24])
    except Exception:
        # print('Failed to get ip address for interface {}.'.format(ifname))
        return None
    else:
        return ip_addr


def get_active_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
    except Exception:
        print('Failed to get a currently active IP address.')
        return None
    else:
        return s.getsockname()[0]


def get_def_route():
    route_cmd = '/sbin/route'
    pattern = re.compile(r'^default\b.*$', re.M)
    stdout, stderr = run_cmd(route_cmd)
    if stdout:
        default_routes = re.finditer(pattern, stdout.decode('utf-8')) # .pop().split()
        first_default_route = next(x for x in default_routes if lambda x: True).group(0).split()
        return first_default_route, stderr.decode('utf-8')
    return None, stderr.decode('utf-8')


def get_net_traffic(t, iface='ppp0'):
    """Example usage for throughput
    while(True):
    tx1 = get_bytes('tx')
    rx1 = get_bytes('rx')

    time.sleep(1)

    tx2 = get_bytes('tx')
    rx2 = get_bytes('rx')

    tx_speed = round((tx2 - tx1)/1000000.0, 4)
    rx_speed = round((rx2 - rx1)/1000000.0, 4)

    print("TX: %fMbps  RX: %fMbps") % (tx_speed, rx_speed)
    """
    # Maybe we can return a total, and some stats, such as bytes per n time, say day and month.
    uptime = round(get_uptime())
    if uptime and uptime > 86400:
        uptime_day = (uptime%86400)
    try:
        with open('/sys/class/net/' + iface + '/statistics/' + t + '_bytes', 'r') as f:
            data = f.read()
            return int(data)
    except IOError as e:
        print('{0} interface doesnt seem to exist.\n{1}'.format(iface, e))
        return None


def get_packet_loss(interface='eth0', samples='1', hostname='8.8.8.8'):
    ping = '/bin/ping'
    cmd = [ping, '-I', interface, '-c', samples, hostname]
    stdout, stderr = run_cmd(cmd)
    try:
        packetloss = float(
            [x for x in stdout.decode('utf-8').split('\n') if x.find('packet loss') != -1]
            [0].split('%')[0].split(' ')[-1])
    except Exception as e:
        print('Failed to get packet loss %.\n{}'.format(e))
        return None
    else:
        return packetloss


def get_net_stats(iface, base_path='/sys/class/net/'):
    stat_dict = {}

    try:
        dir_listing = os.scandir(f'{base_path}{iface}/statistics/')
    except Exception:
        return None

    for file in dir_listing:
        if file.is_file(follow_symlinks=True):
            try:
                with open(file.path, 'r') as f:
                    stat = f.readline()
            except Exception as e:
                print(f'Error opening {file.path}\n\t{e}\nMoving on...')
                pass
            else:
                if stat:
                    stat_dict[file.name] = stat.strip()

    return stat_dict if stat_dict else None


def get_mem_info():
    cmd = ['/usr/bin/free', '-m']
    try:
        stdout, stderr = run_cmd(cmd)
        fields = re.search(r'Mem:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',
                           stdout.decode('utf-8'), re.M).group
    except Exception:
        print('Failed to get memory usage info.')
        return None
    else:
        return dict(total=fields(1),used=fields(2),free=fields(3),
                shared=fields(4),buff_cache=fields(5),available=fields(6))


def get_mem_percent_used():
    meminfo = get_mem_info()
    try:
        percent_used = round((
                (int(meminfo['total']) - int(meminfo['free']))  # This calculation includes cached mem in 'free'.
                / int(meminfo['total']) * 100
        ))
    except Exception as e:
        print(e)
        return None
    else:
        return percent_used


def get_fs_usage(path='/'):
    """Returns percent used for a given filesystem"""
    try:
        disk = os.statvfs(path)
        percent = (disk.f_blocks - disk.f_bfree) * 100 / (disk.f_blocks - disk.f_bfree + disk.f_bavail) + 1
    except Exception:
        print('Failed to get filesyste % used for {}'.format(path))
        return None
    else:
        return percent


def get_sensor_log_stats(path = '/var/spool/redaptive-out'):
    try:
        file_list = list_files(path)
    except Exception:
        print('Failed to get a list of files in {}.'.format(path))
        return None
    else:
        return len(file_list)


def csv_header_from_nested_dict(dictionary):
    header = []
    try:
        for key, value in dictionary.items():
            try:
                for k, v in value.items():
                    header.append(k)
            except AttributeError:
                continue
    except Exception as e:
        print('Failed to auto generate csv header from the nested dictionary {0}\n{1}'.format(dictionary, e))
        return None
    else:
        return header


def csv_row_from_nested_dict(dictionary):
    row = dict()
    try:
        for key, value in dictionary.items():
            try:
                for k, v in value.items():
                    row[k] = v
            except AttributeError:
                continue
    except Exception as e:
        print('Failed generate a csv row from the nested dictionary {0}\n{1}'.format(dictionary, e))
        return None
    else:
        return row


#class NebulaMeter(object):


if __name__ == '__main__':
    '''
    We still need any important config info
    Critical errors, if possible.
    ALSO, !!! utilize the get_net_traffic() function!!!
    .
    .
    .
    '''
    # Grab the subset of meter meta data provided on the filesystem by the RD_accum application.
    rd_accum_metadata = read_run_file('meterMetaData.json')
    # Grab IMS2 metadata provided on the filesystem by the ims2_cmd_interface service.
    ims2_metadata = read_run_file('ims2-metadata.json')

    meter = {
        'macAddress': get_mac(),
        'serial': rd_accum_metadata.get('Serial Num', ''),
        # 'eeprom': {},               # get_eeprom_data()  #Change to get the data from the new rd_accum metadata file.
        'hardwareId': rd_accum_metadata.get('HW ID', ''),
        'system': {},
        'networking': {
            'statistics': {
                'eth0': {},
                'ppp0': {}
            }
        },
        'filesystem': {},
        'software': {
            'meterApp': {},
            'rdAccum': {},
            'networkManager': {},
            'uploadManager': {},
            'ledController': {},
            'ims2CmdInterface': {},
            'mender': {}
        }
    }

    meter['system']['hostname'] = get_hostname()
    meter['system']['systemTime'] = str(get_system_time())
    meter['system']['uptime'] = '{0.days}:{0.hours}:{0.minutes}:{0.seconds}'.format(get_uptime(fancy=True))
    meter['system']['avgLoad'] = get_load_average(1)
    meter['system']['memoryUsed'] = get_mem_percent_used()

    meter['filesystem']['rootFsUsed'] = round(get_fs_usage())
    meter['filesystem']['runFsUsed'] = round(get_fs_usage('/run'))
    meter['filesystem']['redaptiveFsUsed'] = round(get_fs_usage('/var/spool/redaptive'))
    meter['filesystem']['measurementBacklog'] = get_sensor_log_stats()
    meter['filesystem']['meterAppBacklog'] = get_sensor_log_stats('/var/spool/redaptive')

    meter['networking']['eth0MacAddress'] = get_mac()
    meter['networking']['eth0IpAddress'] = get_ip_address('eth0')
    meter['networking']['ppp0IpAddress'] = get_ip_address('ppp0')
    meter['networking']['ActiveIpAddress'] = get_active_ip_address()
    def_iface = get_def_route()[0]
    meter['networking']['defaultInterface'] = def_iface[len(def_iface) - 1] if def_iface else None
    # radio_metadata = get_radio_metadata('ims2MetaData')
    meter['networking']['iccid'] = ims2_metadata.get('iccid', '') if isinstance(ims2_metadata, Mapping) else None
    meter['networking']['apn'] = ims2_metadata.get('apn', '') if isinstance(ims2_metadata, Mapping) else None
    sig_info = get_signal_str()
    meter['networking']['signalStrength'] = sig_info[1] if sig_info else None
    meter['networking']['signalQuality'] = sig_info[2] if sig_info else None
    meter['networking']['cellBand'] = sig_info[3] if sig_info and len(sig_info) >= 4 else None
    meter['networking']['cellTac'] = sig_info[4] if sig_info and len(sig_info) >= 5 else None
    meter['networking']['packetLoss'] = get_packet_loss(meter['networking']['ActiveIpAddress'])

    # !!! Maybe this should be all network statistics for both eth0 and ppp0 (if it exists).  Maybe turn everything in
    # /sys/devices/virtual/net/<interface>/statistics/  into a dictionary, i.e. filename: file_contents
    # meter['networking']['networkErrors'] = None
    meter['networking']['statistics']['eth0'] = get_net_stats('eth0')
    meter['networking']['statistics']['ppp0'] = get_net_stats('ppp0')

    meter['software']['os'] = get_os_version()
    meter['software']['uBoot'] = get_uboot_version()
    meter['software']['kernel'] = get_kernel_version()
    meter['software']['stm32'] = get_software_version('stm32')

    meter['software']['meterApp']['version'] = get_software_version('meter_app')
    meter['software']['meterApp']['pid'] = get_process_info('meter_app')[0]

    meter['software']['rdAccum']['version'] = get_software_version('RD_Accum')
    meter['software']['rdAccum']['packetHeader'] = rd_accum_metadata.get('PKT Ver', '') if rd_accum_metadata else None
    meter['software']['rdAccum']['pid'] = get_process_info('RD_Accum')[0]

    meter['software']['networkManager']['version'] = get_software_checksum(get_process_info('network-manager')[1])[0]
    meter['software']['networkManager']['pid'] = get_process_info('network-manager')[0]

    meter['software']['uploadManager']['version'] = get_software_checksum(importlib.util.find_spec('rdp_upman.uploader').origin)[0]
    meter['software']['uploadManager']['pid'] = get_process_info('rdp_upman.uploader')[0]

    meter['software']['ledController']['version'] = get_software_checksum(get_process_info('led_controller')[1])[0]
    meter['software']['ledController']['pid'] = get_process_info('led_controller')[0]

    meter['software']['ims2CmdInterface']['version'] = get_software_version('ims2-cmd-interface')
    meter['software']['ims2CmdInterface']['pid'] = get_process_info('ims2_cmd_interface')[0]

    meter['software']['mender']['version'] = get_software_version('mender')
    meter['software']['mender']['pid'] = get_process_info('mender')[0]

    # Json to standard out.
    print(dumps(meter))

    # Csv to standard out (using csv module).
    # csv_columns = csv_header_from_nested_dict(meter)
    # row_data = csv_row_from_nested_dict(meter)
    # csv_file = sys_stdout
    # try:
    #     writer = csv.DictWriter(csv_file, fieldnames=csv_columns)
    #     writer.writeheader()
    #     writer.writerow(row_data)
    # except IOError:
    #     print("I/O error")

    # # Csv to standard out (simple txt).
    # rw = csv_row_from_nested_dict(meter)
    # for key, value in rw.items():
    #     print('{}, '.format(value), end = '')
    # print('')

    # /bin/ps | /bin/grep -i '.*/[i]ms2_cmd_interface.py'  use eithshell=true for pipes?
    # /bin/ps | /bin/grep -i '.*/[r]d_accum'
    # /bin/ps | /bin/grep -i '.*[u]ploader'
