#!/bin/python2
# encoding: utf-8
import angr #the main framework
# import claripy #the solver engine
import archinfo
import emoviz # execution trace visualizer
import os, signal
import pickle
import hexdump
# from scapy.all import * # segment faults in pypy

angr.manager.l.setLevel("DEBUG")
angr.state_plugins.view.l.setLevel("DEBUG")

TRACE_SAVE_DIR = "./trace/"
os.system("if [ ! -d %s ]; then mkdir %s; fi" % (TRACE_SAVE_DIR, TRACE_SAVE_DIR))
os.system("rm -f %s[a-zA-Z]*-[0-9]*.{png,dot,txt}" % (TRACE_SAVE_DIR))
def plot_trace():
    global proj, state

    def helper(proj, state, dot_file, plain_file=""):
        ev = emoviz.emoviz(proj)
        ev.add(state)
        ev.save_dot(dot_file)
        ev.save_png(dot_file)
        if plain_file:
            ev.save_plain(plain_file)

    for (i, act) in enumerate(simgr.active):
        dot_file = TRACE_SAVE_DIR + "active-%d.dot" % i
        helper(proj, act.state, dot_file,
            # plain_file=TRACE_SAVE_DIR + "active-%d.txt" % i
            )
        if i >= 9: break
    if hasattr(simgr, "found"):
        for (i, fnd) in enumerate(simgr.found):
            dot_file = TRACE_SAVE_DIR + "found-%d.dot" % i
            helper(proj, fnd.state, dot_file)
    if hasattr(simgr, "avoid"):
        for (i, avd) in enumerate(simgr.avoid):
            dot_file = TRACE_SAVE_DIR + "avoid-%d.dot" % i
            helper(proj, avd.state, dot_file,
                # plain_file=TRACE_SAVE_DIR + "avoid-%d.txt" % i
                )
            if i > 5: break
    for (i, ddd) in enumerate(simgr.deadended):
        dot_file = TRACE_SAVE_DIR + "deadended-%d.dot" % i
        helper(proj, ddd.state, dot_file)
        if i > 5: break
    for (i, err) in enumerate(simgr.errored):
        dot_file = TRACE_SAVE_DIR + "errored-%d.dot" % i
        helper(proj, err.state, dot_file)
        if i >= 14: break

def signal_handler(signal, frame):
    global proj, state
    print('[*] recieved SIGNAL')
    plot_trace()
    exit(1)
signal.signal(signal.SIGINT, signal_handler) # Ctrl+C

def dump_regs(state, _exit=True):
    print "rax = %#x" % state.solver.eval(state.regs.rax)
    print "rdi = %#x" % state.solver.eval(state.regs.rdi)
    print "rsp = %#x" % state.solver.eval(state.regs.rsp)
    print "rbp = %#x" % state.solver.eval(state.regs.rbp)
    # rax = state.solver.eval(state.regs.rax)
    # for i in range(0, 0x38, 8):
    #     print "mem[rax + %#x] = %#x" % (i, state.solver.eval(state.memory.load(rax + i, 8)))
    rbp = state.solver.eval(state.regs.rbp)
    for i in range(0, 0x48, 8):
        print "mem[rbp - %#x] = %#x" % (i, state.solver.eval(state.memory.load(rbp - i, 8)))
    for i in range(0x20000000, 0x20000000 + 0x200, 8):
        # v = state.solver.eval(state.memory.load(i, 8))
        try:
            v = state.mem[i].uint64_t.concrete
        except Exception, e:
            print "mem[%#x]: " % i + str(e)
            continue
        if v > 0:
            print "mem[%#x] = %#x" % (i, v)
    # for i in range(0x1002000000018, 0x1002000000018 + 0x20, 8):
    #     v = state.solver.eval(state.memory.load(i, 8))
    #     if v > 0:
    #         print "mem[%#x] = %#x" % (i, v)
    if _exit:
        exit()

rebased_addr = lambda x: proj.loader.find_symbol(x).rebased_addr

ELF_FILE = "./bin/simhost-STABLE-1_3_1-test"
proj = angr.Project(ELF_FILE, load_options={'auto_load_libs': False})
start_addr = rebased_addr('tcp_input')
print "[*] analysis start: %#x" % start_addr
state = proj.factory.blank_state(addr=start_addr)

### load preprocessed data
from preprocess import Info, Symbol
INFO_FILE = ELF_FILE + ".info"
try:
    with open(INFO_FILE) as f:
        info = pickle.load(f)
except IOError as e:
    print e
    print "[!] run `./preprocess.py %s` first" % (ELF_FILE)
    exit()

def handle_ret_0(state):
    state.regs.rax = 0

def handle_htons(state):
    x = state.regs.rax
    print "==> htons(%#x)" % state.solver.eval(x)
    print "\trbp = %#x" % state.solver.eval(state.regs.ebp)
    """#define PP_HTONS(x) ((u16_t)((((x) & (u16_t)0x00ffU) << 8) | (((x) & (u16_t)0xff00U) >> 8)))"""
    state.regs.rax = (x & 0x00ff << 8) | ((x & 0xff00) >> 8)

try:
    # for x in info.call['htons']:
    #     proj.hook(0x400000 + x, handle_htons, length=5) # 5 byets instruction
    ### nop funtion x() calls
    funcs = [
    "tcp_debug_print_flags", "tcp_debug_print",
    "pbuf_free", "pbuf_realloc",
    "inet_chksum_pseudo", "inet_chksum",
    ]
    for func_name in funcs:
        if func_name in info.call:
            for x in info.call[func_name]:
                proj.hook(0x400000 + x, handle_ret_0, length=5) # 5 byets instruction
        else:
            print "[!] info.call has key '%s'" % func_name
            exit(1)

except Exception as e:
    print e
    import ipdb; ipdb.set_trace()
    raise e

pbuf_ptr = 0x20000000
# pbuf_payload_ptr = pbuf + 0x8
pbuf_payload_ptr = pbuf_ptr + 0x8
pbuf_tot_len = pbuf_ptr + 0x10
pbuf_len = pbuf_ptr + 0x12
pbuf_payload = 0x20000100
# pbuf_payload = 0x1122334455667788
# state.memory.store(pbuf_payload_ptr, pbuf_payload, 8) # pbuf.payload = payload store memory with BIG endian
state.mem[pbuf_payload_ptr].qword = pbuf_payload

symvar_pbuf_tot_len = state.se.BVS('pbuf_tot_len', 16)
state.solver.add(symvar_pbuf_tot_len > 0)
state.memory.store(pbuf_tot_len, symvar_pbuf_tot_len)

symvar_pbuf_len = state.se.BVS('pbuf_len', 16)
state.solver.add(symvar_pbuf_len > 0)
state.solver.add(symvar_pbuf_len != 0x1300)
# state.memory.store(pbuf_len, symvar_pbuf_len, endness=archinfo.Endness.BE)
state.memory.store(pbuf_len, symvar_pbuf_len)
state.add_constraints(symvar_pbuf_tot_len == symvar_pbuf_len)

symvar_pbuf_payload = state.se.BVS('pbuf_payload', 0x100 * 8)
n = symvar_pbuf_payload.size()
bits = [state.se.Extract(i, i, symvar_pbuf_payload) for i in range(n)]
tcp_header_offset = 5 * 4 * 8
state.add_constraints(state.se.Extract(15, 0, symvar_pbuf_payload) == 0x45) # ip version & ip header size (IPHL)
state.add_constraints(state.se.Extract(31, 16, symvar_pbuf_payload) == symvar_pbuf_len) # Total Length in IP header
state.add_constraints(state.se.Extract(32 * 2 + 15, 32 * 2 + 8, symvar_pbuf_payload) == 6) # ip proto (TCP = 6)
# state.add_constraints(state.se.Extract(32 * 3 + 31, 32 * 3 + 0, symvar_pbuf_payload) > 0) # ip src
# state.add_constraints(state.se.Extract(32 * 4 + 31, 32 * 4 + 0, symvar_pbuf_payload) > 0) # ip dest
state.add_constraints(state.se.Reverse(state.se.Extract(32 * 3 + 31, 32 * 3 + 0, symvar_pbuf_payload)) == 0xc0a80001) # ip src (192.168.0.1)
state.add_constraints(state.se.Reverse(state.se.Extract(32 * 4 + 31, 32 * 4 + 0, symvar_pbuf_payload)) == 0xc0a80002) # ip dest (192.168.0.2)
state.add_constraints(state.solver.Extract(tcp_header_offset + 0xf, tcp_header_offset + 0x0, symvar_pbuf_payload) != 20) # src port
state.add_constraints(state.solver.Extract(tcp_header_offset + 0x1f, tcp_header_offset + 0x10, symvar_pbuf_payload) != 80) # dst port
state.add_constraints(state.solver.Extract(tcp_header_offset + 0x3f, tcp_header_offset + 0x20, symvar_pbuf_payload) == 0x11223344) # seqno
state.add_constraints(state.solver.Extract(tcp_header_offset + 0x5f, tcp_header_offset + 0x40, symvar_pbuf_payload) == 0x55667788) # ackno
# state.add_constraints(state.solver.Extract(tcp_header_offset + 96 + 7, tcp_header_offset + 96 + 4, symvar_pbuf_payload) >= 0x5)
symvar_tcp_dataofs = state.solver.Extract(tcp_header_offset + 96 + 7, tcp_header_offset + 96 + 4, symvar_pbuf_payload)
# state.solver.add(state.se.And(symvar_tcp_dataofs >= 5, symvar_tcp_dataofs <= 15)) # tcp length
state.solver.add(state.se.And(symvar_tcp_dataofs == 5)) # tcp length
state.memory.store(pbuf_payload, state.se.Reverse(symvar_pbuf_payload))

dump_regs(state, _exit=False)

RSP = 0x7fff1000
state.regs.rdi = pbuf_ptr
state.regs.rsi = 0 # inp_ptr

simgr = proj.factory.simgr(state)

find, avoid = [], []
find += [rebased_addr('congratz')]
avoid += [rebased_addr('abort')]
# avoid += [rebased_addr('pbuf_free')]

print "[*] find = %s" % str(map(lambda x: hex(x), find))
print "[*] avoid = %s" % str(map(lambda x: hex(x), avoid))

### debugging
# proj.hook(0x400000 + 0x1cc38, dump_regs, length=4)
# proj.hook(0x400000 + 0x1cc0a, dump_regs, length=4)
# proj.hook(0x400000 + 0x1cc59, dump_regs, length=4)

simgr.explore(find=find, avoid=avoid)

plot_trace()

def memory_dump(state, begin, length):
    ret = ""
    for i in range(0, length):
        val = state.solver.eval(state.memory.load(begin + i, 1))
        ret += chr(val)
    return ret

result = open("result.py", "w")
result.write("""
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
""")
for i, found in enumerate(simgr.found):
    print "found #%d: pbuf.tot_len: %#x" % (i, found.solver.eval(symvar_pbuf_tot_len))
    print "found #%d: pbuf.len: %#x" % (i, found.solver.eval(symvar_pbuf_len))

    print "found #%d: pbuf.payload: " % (i)
    v = found.solver.eval(found.se.Reverse(symvar_pbuf_payload), cast_to=str)
    # v = memory_dump(pbuf_payload_ptr, 0x100)
    result.write("""
print("found #%d: pbuf.payload:")
v = pickle.loads(%r)
p = IP(_pkt=v)
p[IP].ttl = 64
p[IP].window = 8192
p.show()
if IS_ROOT and PACKET_NO == %d:
    p[TCP].chksum = 0xa4f8 # Fix Me!
    p.show()
    send(p)
else:
    # hexdump(v)
    pass
""" % (i, pickle.dumps(v), i))
    print "found #%d: pbuf:" % (i)
    v = memory_dump(found, pbuf_ptr, 0x20)
    hexdump.hexdump(v)
    tcphdr_val = found.mem[rebased_addr('tcphdr')].uint64_t.concrete
    iphdr_val = found.mem[rebased_addr('iphdr')].uint64_t.concrete
    print "found #%d: iphdr = %#x, tcphdr = %#x" % (i, iphdr_val, tcphdr_val)
    print "found #%d: *iphdr:" % (i)
    hexdump.hexdump(memory_dump(found, iphdr_val, 0x20))
    print "found #%d: *tcphdr:" % (i)
    hexdump.hexdump(memory_dump(found, tcphdr_val, 0x20))
result.close()
print ""
os.system("python2 result.py")