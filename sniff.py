import socket, sys
from struct import *
from time import time
import logging

LOG_FORMAT = "%(asctime)-15s %(clientip)s %(message)s"
LOG_FORMAT_STATUS = "%(asctime)-15s %(message)s"
logging.basicConfig(format=LOG_FORMAT_STATUS, filename='/var/log/pysniff.log', level=20)

__program__ = sys.argv[0]
pps_tracker = {}
local_addresses = []

def get_local_net_addresses():
    from netifaces import interfaces, ifaddresses, AF_INET
    ip_list = []
    for interface in interfaces():
        for link in ifaddresses(interface)[AF_INET]:
            ip_list.append(link['addr'])
    return ip_list

def pps_track_ip(ip, pkt_len):
    global pps_tracker
    if ip in local_addresses:
        return
    if ip in list(pps_tracker): #.keys():
        pps_tracker[ip]['ltime'] = time()
        pps_tracker[ip]['packets'] += 1
        pps_tracker[ip]['bytes'] += pkt_len
    else:
        stime = time()
        pps_tracker[ip] = {'stime':stime,'ltime':stime,
            'packets':1, 'bytes':pkt_len}

def pps_cleanup():
    global pps_tracker
    MINPPS = 0.75
    MAXTIME = 60.0 * 5.0 #remove if five minutes of no packets
    for ip in list(pps_tracker): #.keys():
        last_seen = time() - pps_tracker[ip]['ltime']
        duration = time() - pps_tracker[ip]['stime']
        if duration < 1.0:
            continue
        pps = pps_tracker[ip]['packets'] / duration
        if last_seen > MAXTIME or pps < MINPPS:
            logging.info("%s remove last_seen=%.2fs" % (ip, last_seen))
            del(pps_tracker[ip])

def pps_status():
    MAXRATE = 60
    for ip in list(pps_tracker): #.keys():
        duration = time() - pps_tracker[ip]['stime']
        if duration < 1.0:
            continue
        pps = pps_tracker[ip]['packets'] / duration
        bytes_ps = pps_tracker[ip]['bytes'] / duration
        kbits_ps = bytes_ps / 1024
        logging.info("%s pps=%.2f kbps=%.2f duration=%.2fs packets=%d" % (
            ip, pps, kbits_ps, duration, pps_tracker[ip]['packets']))

def eth_addr (a) :
  b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (
    ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
  return b
 
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except socket.error as msg:
    print('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit(1)
 
last_cleanup = time()
local_addresses = get_local_net_addresses()
logging.info("Not tracking local addresses: %s" % (local_addresses))
while True:
    packet = s.recvfrom(65565)
    packet = packet[0]
    eth_length = 14
    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH' , eth_header)
    eth_protocol = socket.ntohs(eth[2])
    if eth_protocol == 8 :
        runtime = time() - last_cleanup
        #print(runtime)
        if runtime > 10:
            logging.info("cleanup-start")
            cleanup_start = time()
            pps_cleanup()
            pps_status()
            last_cleanup = time()
            logging.info("cleanup-end time=%.2fs" % (cleanup_start - last_cleanup))

        ip_header = packet[eth_length:20+eth_length]
        iph = unpack('!BBHHHBBH4s4s' , ip_header)
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
        pps_track_ip(s_addr, len(packet))
        pps_track_ip(d_addr, len(packet))
        #version_ihl = iph[0]
        #version = version_ihl >> 4
        #ihl = version_ihl & 0xF
        #iph_length = ihl * 4
        #ttl = iph[5]
        #protocol = iph[6]
