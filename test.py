import socket
import fcntl
import struct

def get_ip_address( NICname ):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', NICname[:15].encode("UTF-8"))
    )[20:24])

def get_all_ip_addresses():
    nic = []
    for ix in socket.if_nameindex():
        name = ix[1]
        ip = get_ip_address(name)
        nic.append((name, ip))
    return nic


print(get_all_ip_addresses())
