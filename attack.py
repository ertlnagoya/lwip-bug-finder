
import pickle
from scapy.all import *
import sys

IS_ROOT = (os.geteuid() == 0)
PACKET_NO = -1
if len(sys.argv) == 2:
    PACKET_NO = int(sys.argv[1])
if PACKET_NO > 0 and not IS_ROOT:
    print "[!] sudo first to send packet!"
    exit(1)
if IS_ROOT and PACKET_NO == -1:
    print "[!] specify packet no"
    exit(1)

# def checksum(msg):
#     s = 0
#     for i in range(0, len(msg), 2):
#         w = ord(msg[i]) + (ord(msg[i+1]) << 8)
#         s = carry_around_add(s, w)
#     return ~s & 0xffff

def checksum(msg, hdr_len):
    ret = 0
    i = 0
    while (hdr_len > 1):
        ret += ord(msg[i]) + (ord(msg[i+1]) << 8)
        if (ret & 0x80000000):
            ret = (ret & 0xFFFF) + (ret >> 16)
        hdr_len -= 2
        i += 2
    while (ret >> 16):
        ret = (ret & 0xFFFF) + (ret >> 16)
    return ~ret & 0xFFFF

print("found #0: pbuf.payload:")
v = pickle.loads('S\'E\\x00\\x00\\x15\\x00\\x00\\x00\\x00\\x00\\x06\\x00\\x00\\xc0\\xa8\\x00\\x01\\xc0\\xa8\\x00\\x02\\x00\\x14\\x00P\\x11"3DUfw\\x88`\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\'\np0\n.')
p = IP(_pkt=v)
p[IP].flags = 0
p[IP].ttl = 64
p[IP].window = 8192
p[IP].chksum = None
# print "checksum = %#x" % checksum(bytes(p)[:p[IP].ihl*4], p[IP].ihl*4)
# p[IP].chksum = abs(checksum(bytes(p)[:p[IP].ihl*4], p[IP].ihl*4))
p.show2()
if IS_ROOT and PACKET_NO == 0:
    p[TCP].chksum = None
    p.show2()
    send(p)
else:
    # hexdump(v)
    pass
