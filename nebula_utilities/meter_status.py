import importlib.util
from collections import namedtuple
from datetime import datetime
import os
import re
import uuid
import subprocess
import socket
import fcntl
import struct

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
            return v[0].split()[0].decode().strip()
        else:
            return None


def get_checksum(name):
    # try to get the path from ps and get a checksum for the file.
    pass

def get_pid( name):
    # maybe use first five characters of name, case insensative, to get the pid and also derive the file path for checksums.
    # /bin/ps | /bin/grep -i '.*/[i]ms2_cmd_interface.py'  use eithshell=true for pipes?
    # /bin/ps | /bin/grep -i '.*/[r]d_accum'
    # /bin/ps | /bin/grep -i '.*[u]ploader'
    pass

def get_ps_data(name):
    # maybe use first five characters of name, case insensative, to get the pid and also derive the file path for checksums.
    # /bin/ps | /bin/grep -i '.*/[i]ms2_cmd_interface.py'  use eithshell=true for pipes?
    # /bin/ps | /bin/grep -i '.*/[r]d_accum'
    # /bin/ps | /bin/grep -i '.*[u]ploader'
    pid = ''
    path = ''
    return pid, path


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


def get_uptime():
    try:
        with open('/proc/uptime', 'r') as f:
            uptime_seconds = float(f.readline().split()[0])
    except Exception:
        print('failed to get system uptime')
        return None
    else:
        return uptime_seconds


def normalize_seconds(seconds: int) -> tuple or None:
    try:
        (days, remainder) = divmod(seconds, 86400)
        (hours, remainder) = divmod(remainder, 3600)
        (minutes, seconds) = divmod(remainder, 60)
    except Exception as e:
        print('Failed to convert seconds to d:m:h:s.\n{}'.format(e))
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
        print(e)
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
        print('Failed to get ip address for interface {}.'.format(ifname))
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


def get_packet_loss(interface='ppp0', samples='1', hostname='8.8.8.8'):
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


if __name__ == '__main__':
    system = {}
    networking = {}
    filesystem = {}
    software = {}

    # !!! Make all methods return None on exception, so we always have something stored.
    system['hostname'] = get_hostname()
    system['system_time'] = get_system_time()
    system['uptime'] = round(get_uptime()/60)
    system['loadavg'] = get_load_average(1)
    system['mem_used'] = get_mem_percent_used()

    filesystem['root_fs_used'] = round(get_fs_usage())
    filesystem['run_fs_used'] = round(get_fs_usage('/run'))
    filesystem['redaptive_fs_used'] = round(get_fs_usage('/var/spool/redaptive'))
    filesystem['measurement_backlog'] = get_sensor_log_stats()
    filesystem['meter_app_backlog'] = get_sensor_log_stats('/var/spool/redaptive')

    networking['mac_eth0'] = get_mac()
    networking['ip_addr_eth0'] = get_ip_address('eth0')
    networking['ip_addr_ppp0'] = get_ip_address('ppp0')
    networking['ip_addr_active'] = get_active_ip_address()
    def_iface = get_def_route()[0]
    networking['default_iface'] = def_iface[len(def_iface) - 1]
    networking['iccid'] = 'NA'
    networking['apn'] = 'NA'
    sig_info = get_signal_str()
    if sig_info:
        networking['sig_str'] = sig_info[1]
        networking['sig_qual'] = sig_info[2]
    networking['packet_loss'] = get_packet_loss()
    networking['network_errors'] = ''

    software['redrock_os'] = get_os_version()
    software['u-boot'] = 'NA'
    software['kernel'] = 'NA'
    software['stm32'] = get_software_version('stm32')
    software['meter-app'] = get_software_version('meter-app')
    software['rd-accum'] = get_software_version('rd-accum')
    software['network-manager'] = 'NA'
    software['upload-manager'] = 'NA'
    software['led-controller'] = 'NA'
    software['ims2-cmd-interface'] = get_software_version('ims2-cmd-interface')
    software['mender'] = get_software_version('mender')

    print('System Data:')
    for key, value in system.items():
        print('{0}:\t{1}'.format(key, value))

    print('\nFilesystem Data:')
    for key, value in filesystem.items():
        print('{0}:\t{1}'.format(key, value))

    print('\nNetworking Data:')
    for key, value in networking.items():
        print('{0}:\t{1}'.format(key, value))

    print('\nSoftware Data:')
    for key, value in software.items():
        print('{0}:\t{1}'.format(key, value))
