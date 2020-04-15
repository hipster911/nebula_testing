import importlib.util
from collections import namedtuple
from datetime import datetime
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
import pathlib
import csv


def read_run_file(name):
    run_path = '/run/'
    try:
        with open('{0}{1}'.format(run_path, name), 'r') as f:
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
            return v[0].split()[5].decode().strip()
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
        return None

    # Read the file (in chunks; to prevent choking the RAM when reading large files).
    try:
        with open(file, "rb") as f:
            while True:
                file_data = f.read(8192)  # Block size = 8192 Bytes (8 KB)
                if not file_data:
                    break
                hash_func.update(file_data)
    except Exception as e:
        print('Error calculating checksum fo file {0}!\n{1}'.format(file, e))
        return None
    else:
        return hash_func.hexdigest(), \
               algorithm, \
               file, \
               os.path.getsize(file)


def get_eeprom_data():
    # shell version of grabbing our hardware id data stored at i2c bus 0, chip address 0x50, data bytes 0x20-0x22:
    # Set the pointer at the bit you want
    # i2cset -y 0 0x50 0x20 0x20
    # Get the data at that location, and the adjacent 2 bytes as well.
    # i2cget -y 0 0x50     # Returns the byte at the current pointer, set above, and advances the pointer 1, to 0x21.
    # i2cget -y 0 0x50     # Returns the byte at the current pointer, set above, and advances the pointer 1, to 0x22.
    # i2cget -y 0 0x50     # Returns the byte at the current pointer, set above, and advances the pointer 1, to 0x23.

    from smbus2 import SMBus
    byte_count = 0
    hardware_id = {}
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
    print(hardware_id)
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
    if processes: return processes


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
                return pid, process[path_index[0]] # If there are multiple instances, only return the first.
    return None


def run_cmd(*args, **kwargs):
    try:
        process = subprocess.Popen(*args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)
    except Exception as e:
        print(e)
        return None
    else:
        return  process.communicate()  # returns (stdout, stderr)


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


def get_signal_str(path = '/var/spool/redaptive'):
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


def get_mac():
    try:
        return ':'.join(re.findall('..', '%012x' % uuid.getnode()))
    except Exception:
        print('Failed to get system MAC address.')
        return None


def get_ip_address(ifname = 'eth0'):
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
    .
    .
    .
    '''
    meter = {
        'mac_addr': get_mac(),
        'system': {},
        'networking': {},
        'filesystem': {},
        'software': {}
    }

    meter['system']['hostname'] = get_hostname()
    meter['system']['system_time'] = str(get_system_time())
    meter['system']['uptime'] =  '{0.days}:{0.hours}:{0.minutes}:{0.seconds}'.format(get_uptime(fancy=True))
    meter['system']['loadavg'] = get_load_average(1)
    meter['system']['mem_used'] = get_mem_percent_used()

    meter['filesystem']['root_fs_used'] = round(get_fs_usage())
    meter['filesystem']['run_fs_used'] = round(get_fs_usage('/run'))
    meter['filesystem']['redaptive_fs_used'] = round(get_fs_usage('/var/spool/redaptive'))
    meter['filesystem']['measurement_backlog'] = get_sensor_log_stats()
    meter['filesystem']['meter_app_backlog'] = get_sensor_log_stats('/var/spool/redaptive')

    meter['networking']['mac_eth0'] = get_mac()
    meter['networking']['ip_addr_eth0'] = get_ip_address('eth0')
    meter['networking']['ip_addr_ppp0'] = get_ip_address('ppp0')
    meter['networking']['ip_addr_active'] = get_active_ip_address()
    def_iface = get_def_route()[0]
    meter['networking']['default_iface'] = def_iface[len(def_iface) - 1] if def_iface else None
    meter['networking']['iccid'] = None
    meter['networking']['apn'] = None
    sig_info = get_signal_str()
    meter['networking']['sig_str'] = sig_info[1] if sig_info else None
    meter['networking']['sig_qual'] = sig_info[2] if sig_info else None
    meter['networking']['cell_band'] = sig_info[3] if sig_info and len(sig_info) >= 4 else None
    meter['networking']['cell_tac'] = sig_info[4] if sig_info and len(sig_info) >= 5 else None
    meter['networking']['packet_loss'] = get_packet_loss(meter['networking']['ip_addr_active'])
    meter['networking']['network_errors'] = None

    ''' !!! WE NEED TO ADD PID's FOR IMPORTANT PROCESSES, SO WE CAN FLAG HIGH PID COUNTS. !!!'''
    meter['software']['redrock_os'] = get_os_version()
    meter['software']['u-boot'] = get_uboot_version()
    meter['software']['kernel'] = get_kernel_version()
    meter['software']['stm32'] = get_software_version('stm32')
    meter['software']['meter-app'] = get_software_version('meter-app')
    meter['software']['rd-accum'] = get_software_version('rd-accum')
    meter['software']['network-manager'] = get_software_checksum(get_process_info('network-manager')[1])[0]
    meter['software']['upload-manager'] = get_software_checksum(importlib.util.find_spec('rdp_upman.uploader').origin)[0]
    meter['software']['led-controller'] = get_software_checksum(get_process_info('led_controller')[1])[0]
    meter['software']['ims2-cmd-interface'] = get_software_version('ims2-cmd-interface')
    meter['software']['mender'] = get_software_version('mender')

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
