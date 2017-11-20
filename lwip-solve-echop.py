#!/usr/bin/python2
# encoding: utf-8
import angr #the main framework
import claripy #the solver engine
try:
    import emoviz # execution trace visualizer
except ImportError as e:
    print e
    print "[!] cannot load emoviz module. missing emoviz.py in current directory. exit."
    exit(1)
import os, sys, signal
import pickle
import hexdump

angr.manager.l.setLevel("DEBUG")

### ==================================================================
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
        if i >= 15: break
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
    print('[*] received SIGNAL')
    plot_trace()
    exit(1)
signal.signal(signal.SIGINT, signal_handler) # Ctrl+C
### ==================================================================

def dump_regs(state, _exit=True):
    global symvar_listen_pcbs, symbar_netif
    print "rax = %#x" % state.solver.eval(state.regs.rax)
    print "rdi = %#x" % state.solver.eval(state.regs.rdi)
    print "rsp = %#x" % state.solver.eval(state.regs.rsp)
    print "rbp = %#x" % state.solver.eval(state.regs.rbp)
    rbp = state.solver.eval(state.regs.rbp)
    for i in range(0, 0x48, 8):
        # print "mem[rbp - %#x] = %#x" % (i, state.solver.eval(state.memory.load(rbp - i, 8)))
        print "mem[rbp - %#x] = %#x" % (i, state.mem[rbp - i].uint64_t.concrete)
    for i in range(0x20000000, 0x20000000 + 0x200, 8):
        # v = state.solver.eval(state.memory.load(i, 8))
        try:
            v = state.mem[i].uint64_t.concrete
        except Exception, e:
            print "mem[%#x]: " % i + str(e)
            continue
        if v > 0:
            print "mem[%#x] = %#x" % (i, v)
    print "listen_pcbs:"
    v = state.se.eval(state.se.Reverse(symvar_listen_pcbs), cast_to=str)
    hexdump.hexdump(v)
    if _exit:
        exit()

def memory_dump(state, begin, length):
    ret = ""
    for i in range(0, length):
        val = state.solver.eval(state.memory.load(begin + i, 1))
        ret += chr(val)
    return ret

def sizeof(symbol_name):
    global info
    return info.symbols[symbol_name].size

def usage():
    print "usage: %s START_FUNC_NAME" % (sys.argv[0])
    exit(1)

### === helper functions ===
rebased_addr = lambda x: proj.loader.find_symbol(x).rebased_addr
relative_addr = lambda x: proj.loader.find_symbol(x).relative_addr
NoReverse = lambda x: x
BigEndian = lambda x: state.se.Reverse(x)
LittleEndian = lambda x: x

### process argv
if len(sys.argv) == 1:
    usage()
START_FUNC = sys.argv[1]
if START_FUNC not in ['tcp_input', 'udp_input', 'etharp_arp_input', 'dns_recv']:
    print "[!] invalid function name"
    exit(1)

### load binary
ELF_FILE = "./bin/echop-STABLE-1_3_0"
proj = angr.Project(ELF_FILE, load_options={'auto_load_libs': False})
start_addr = rebased_addr(START_FUNC)
print "[*] analysis start: %#x" % start_addr

### create blank state (initial state)
state = proj.factory.blank_state(addr=start_addr)

### map new region for my symbolic variables
"""memo
gdb-peda$ vmmap
Start              End                Perm  Name
0x00400000         0x00418000         r-xp  /home/tomori/lwip/lwip-bug-finder/bin/echop-STABLE-1_3_0
0x00617000         0x00618000         r--p  /home/tomori/lwip/lwip-bug-finder/bin/echop-STABLE-1_3_0
0x00618000         0x00619000         rw-p  /home/tomori/lwip/lwip-bug-finder/bin/echop-STABLE-1_3_0
0x00619000         0x00620000         rw-p  mapped
0x015ae000         0x015cf000         rw-p  [heap]
"""
MY_SYMVAR_REGION_BEGIN = 0x20000000
MY_SYMVAR_REGION_LENGTH = 0x1000000
state.memory.mem.map_region(MY_SYMVAR_REGION_BEGIN, MY_SYMVAR_REGION_LENGTH, 0b111) # begin, len, permissions
MAPPED_BEGIN = 0x00619000
MAPPED_LENGTH = 0x3000
# state.memory.mem.map_region(MAPPED_BEGIN, MAPPED_LENGTH, 0b111) # begin, len, permissions # Already mapped?

### change options
state.options.add("STRICT_PAGE_ACCESS") # to handle SEGV
state.options.add("REPLACEMENT_SOLVER")
# import ipdb; ipdb.set_trace()

### helper boolean
tcp = (start_addr == rebased_addr('tcp_input'))
udp = (start_addr == rebased_addr('udp_input')) or (start_addr == rebased_addr('dns_recv'))
dns = (start_addr == rebased_addr('dns_recv'))
etharp_arp = (start_addr == rebased_addr('etharp_arp_input'))
ip = tcp or udp

### load preprocessed data
print "[*] loading preprocessed data"
from preprocess import Info, Symbol
INFO_FILE = ELF_FILE + ".info"
try:
    with open(INFO_FILE) as f:
        info = pickle.load(f)
except IOError as e:
    print e
    print "[!] run `./preprocess.py %s` first" % (ELF_FILE)
    exit()

### disables function calls. and sets return value 0
def handle_ret_0(state):
    state.regs.rax = 0

### hooks function calls
try:
    ### nop function x() calls
    funcs = []
    if dns:
        # funcs += [
        # ]
        pass
    else:
        funcs += [
        "tcp_debug_print_flags", "tcp_debug_print",
        "udp_debug_print", # debug output
        "__printf_chk", # ??
        "inet_chksum_pseudo", # checksum check
        "inet_chksum_pseudo_partial",
        # "tcp_process", # tcp state machine
        # "pbuf_free",
        "sys_arch_protect", "sys_arch_unprotect", # SYS_ARCH_PROTECT, SYS_ARCH_UNPROTECT
        "sys_arch_sem_wait",
        ]
    for func_name in funcs:
        if func_name in info.call:
            for x in info.call[func_name]:
                proj.hook(0x400000 + x, handle_ret_0, length=5) # 5 bytes instruction
        else:
            print "[!] info.call has not key '%s'" % func_name
            exit(1)
except Exception as e:
    print e
    import ipdb; ipdb.set_trace()
    raise e

### enable debug flag
print "[*] enabling debug_flag"
LWIP_DBG_ON = 0x80
LWIP_DBG_OFF = 0x0
state.mem[rebased_addr('debug_flags')].uint32_t = LWIP_DBG_OFF

### symbolize pbuf
print "[*] symbolizing pbuf"
"""
gdb-peda$ p (struct pbuf) *$rdi
$4 = {
  next = 0x0,
  payload = 0x560bea7cbe9e <memp_memory+19006>,
  tot_len = 0x30,
  len = 0x30,
  type = 0x3,
  flags = 0x0,
  ref = 0x1
}
gdb-peda$ x/8wx $rdi
0x560bea7cbe78 <memp_memory+18968>: 0x00000000  0x00000000  0xea7cbe9e  0x0000560b
0x560bea7cbe88 <memp_memory+18984>: 0x00300030  0x00010003  0x04030201  0xa6920605 // + 16
"""
pbuf_ptr = MY_SYMVAR_REGION_BEGIN
pbuf_next = pbuf_ptr + 0x0
pbuf_payload_ptr = pbuf_ptr + 0x8
pbuf_tot_len = pbuf_ptr + 0x10
pbuf_len = pbuf_ptr + 0x12
pbuf_type = pbuf_ptr + 0x14
pbuf_flags = pbuf_ptr + 0x15
pbuf_ref = pbuf_ptr + 0x16
# pbuf_payload = MAPPED_BEGIN # pbuf is located in section "mapped"
pbuf_payload = 0x61f7a2

state.mem[pbuf_next].qword = 0 # NULL
state.mem[pbuf_payload_ptr].qword = pbuf_payload # => p->payload == pbuf_payload

### symbolize pbuf.tot_len
symvar_pbuf_tot_len = state.se.BVS('pbuf_tot_len', 16) # u16_t
# state.add_constraints(symvar_pbuf_tot_len > 0)
state.add_constraints(symvar_pbuf_tot_len == 0x3e)
state.memory.store(pbuf_tot_len, state.se.Reverse(symvar_pbuf_tot_len))

### symbolize pbuf.len
symvar_pbuf_len = state.se.BVS('pbuf_len', 16) # u16_t
state.add_constraints(symvar_pbuf_tot_len == symvar_pbuf_len)
ip_min_len = 20
min_len = 0
if dns:
    min_len = 0x3e
elif tcp:
    min_len = ip_min_len + 20
elif udp:
    min_len = ip_min_len + 64 / 8
### limit `<= 256` avoids 'IP (len %d) is longer than pbuf (len 256), IP packet dropped.''
state.add_constraints(state.se.And(symvar_pbuf_len >= min_len, symvar_pbuf_len <= 256))
state.memory.store(pbuf_len, state.se.Reverse(symvar_pbuf_len))

### symbolize pbuf.type
symvar_pbuf_type = state.se.BVS('pbuf_type', 8)
# state.add_constraints(symvar_pbuf_type == 0x3)
state.add_constraints(state.se.Or(symvar_pbuf_type == 0x0, symvar_pbuf_type == 0x3))
state.memory.store(pbuf_type, state.se.Reverse(symvar_pbuf_type))

### symbolize pbuf.ref
symvar_pbuf_ref = state.se.BVS('pbuf_ref', 16)
state.add_constraints(symvar_pbuf_ref == 1) # reference count
state.memory.store(pbuf_ref, state.se.Reverse(symvar_pbuf_ref))

### add constraints for a packet
L2_PAYLOAD_MAX_LEN = 1500 # 1518 (max Ether frame size) - 14 (address) - 4 (FCS)
symvar_pbuf_payload = state.se.BVS('pbuf_payload', L2_PAYLOAD_MAX_LEN * 8)
tcp_header_offset = 5 * 4 * 8
"""
gdb-peda$ x/12wx p->payload
0x61f7a2 <memp_memory+8930>:    0x80810000  0xffff0100  0x00000000  0x77777703
0x61f7b2 <memp_memory+8946>:    0x6f6f6706  0x03656c67  0x006d6f63  0x01000100
0x61f7c2 <memp_memory+8962>:    0x77777703  0x6f6f6706  0x03656c67  0x006d6f63
0x61f7d2 <memp_memory+8978>:    0x01000100  0x00000000  0x007f0400  0x000c0100
"""
state.add_constraints(LittleEndian(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_pbuf_payload)) == 0x80810000)
# state.add_constraints(LittleEndian(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pbuf_payload)) == 0x02000100) # Answer RRs = 2
state.add_constraints(LittleEndian(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pbuf_payload)) == 0xff000100) # Answer RRs
state.add_constraints(LittleEndian(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_pbuf_payload)) == 0)
state.add_constraints(LittleEndian(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_pbuf_payload)) == 0x77777703)
state.add_constraints(LittleEndian(state.se.Extract(8 * 20 - 1, 8 * 16, symvar_pbuf_payload)) == 0x6f6f6706)
state.add_constraints(LittleEndian(state.se.Extract(8 * 24 - 1, 8 * 20, symvar_pbuf_payload)) == 0x03656c67)
state.add_constraints(LittleEndian(state.se.Extract(8 * 28 - 1, 8 * 24, symvar_pbuf_payload)) == 0x006d6f63)
state.add_constraints(LittleEndian(state.se.Extract(8 * 32 - 1, 8 * 28, symvar_pbuf_payload)) == 0x01000100)
state.add_constraints(LittleEndian(state.se.Extract(8 * 36 - 1, 8 * 32, symvar_pbuf_payload)) == 0x77777703)
state.add_constraints(LittleEndian(state.se.Extract(8 * 40 - 1, 8 * 36, symvar_pbuf_payload)) == 0x6f6f6706)
state.add_constraints(LittleEndian(state.se.Extract(8 * 44 - 1, 8 * 40, symvar_pbuf_payload)) == 0x03656c67)
state.add_constraints(LittleEndian(state.se.Extract(8 * 48 - 1, 8 * 44, symvar_pbuf_payload)) == 0x006d6f63)
state.add_constraints(LittleEndian(state.se.Extract(8 * 52 - 1, 8 * 48, symvar_pbuf_payload)) == 0x01000100)
state.add_constraints(LittleEndian(state.se.Extract(8 * 56 - 1, 8 * 52, symvar_pbuf_payload)) == 0)
# state.add_constraints(LittleEndian(state.se.Extract(8 * 60 - 1, 8 * 56, symvar_pbuf_payload)) == 0x007f0400)
state.add_constraints(LittleEndian(state.se.Extract(8 * 60 - 1, 8 * 56, symvar_pbuf_payload)) == 0x007fffff)
state.add_constraints(LittleEndian(state.se.Extract(8 * 64 - 1, 8 * 60, symvar_pbuf_payload)) == 0x000c0100)
state.memory.store(pbuf_payload, state.se.Reverse(symvar_pbuf_payload))

print "[*] pbuf->payload"
v = state.se.eval(state.se.Reverse(symvar_pbuf_payload), cast_to=str)
hexdump.hexdump(v[:0x40])
# exit()

### symbolize tcp/udp pcbs
print "[*] symbolizing tcp/udp pcbs"
"""
gdb-peda$ p tcp_listen_pcbs
$6 = {
  listen_pcbs = 0x560bea7c7b28 <memp_memory+1736>,
  pcbs = 0x560bea7c7b28 <memp_memory+1736>
}
gdb-peda$ p *(tcp_listen_pcbs->listen_pcbs)
$8 = {
  local_ip = {
    addr = 0x0
  },
  remote_ip = {
    addr = 0x560b
  },
  so_options = 0x2,
  tos = 0x0,
  ttl = 0xff,
  next = 0x560bea7c7b60 <memp_memory+1792>,
  state = LISTEN,
  prio = 0x0,
  callback_arg = 0x560bea7c8250 <memp_memory+3568>,
  local_port = 0x7,
  accept = 0x560bea5a9039 <accept_function>
}
gdb-peda$ x/20wx (tcp_listen_pcbs->listen_pcbs)
0x560bea7c7b28 <memp_memory+1736>:  0x00000000  0x0000560b  0xff000002  0x00000000
0x560bea7c7b38 <memp_memory+1752>:  0xea7c7b60  0x0000560b  0x00000001  0x00000000 // + 16
0x560bea7c7b48 <memp_memory+1768>:  0xea7c8250  0x0000560b  0x00000007  0x00000000 // + 32
0x560bea7c7b58 <memp_memory+1784>:  0xea5a9039  0x0000560b  0x00000000  0x0000560b // + 48
0x560bea7c7b68 <memp_memory+1800>:  0xff000002  0x00000000  0xea7c7b98  0x0000560b

gdb-peda$ x/20wx (tcp_listen_pcbs->listen_pcbs)->callback_arg
0x560bea7c8250 <memp_memory+3568>:  0x00000010  0x00000002  0xea7c7b28  0x0000560b
0x560bea7c8260 <memp_memory+3584>:  0x00000000  0x00000000  0xec000b10  0x00007fd4
0x560bea7c8270 <memp_memory+3600>:  0x00000000  0x00000000  0xe8000f40  0x00007fd4
0x560bea7c8280 <memp_memory+3616>:  0xffffffff  0x00000000  0x00000000  0x00000000
0x560bea7c8290 <memp_memory+3632>:  0x00000000  0x00000000  0x00000000  0x00000000
"""
listen_pcbs = MY_SYMVAR_REGION_BEGIN + 0x10000
callback_arg = listen_pcbs + sizeof("tcp_listen_pcbs")
# state.mem[rebased_addr('tcp_listen_pcbs')].uint64_t = state.se.Reverse(state.se.BVV(listen_pcbs, 64))
state.mem[rebased_addr('tcp_listen_pcbs')].uint64_t = listen_pcbs
state.mem[callback_arg + 0].uint32_t = 0x00000010
state.mem[callback_arg + 4].uint32_t = 0x00000002
symvar_listen_pcbs = state.se.BVS('listen_pcbs', 56 * 8)
symvar_listen_pcbs_state = state.se.BVS('listen_pcbs', 4 * 8)
"""
include/lwip/tcpbase.h
enum tcp_state {
  CLOSED      = 0,
  LISTEN      = 1,
  SYN_SENT    = 2,
  SYN_RCVD    = 3,
  ESTABLISHED = 4,
  FIN_WAIT_1  = 5,
  FIN_WAIT_2  = 6,
  CLOSE_WAIT  = 7,
  CLOSING     = 8,
  LAST_ACK    = 9,
  TIME_WAIT   = 10
};
"""
"""
  for(pcb = tcp_active_pcbs; pcb != NULL; pcb = pcb->next) {
    LWIP_ASSERT("tcp_input: active pcb->state != CLOSED", pcb->state != CLOSED);
    LWIP_ASSERT("tcp_input: active pcb->state != TIME-WAIT", pcb->state != TIME_WAIT);
    LWIP_ASSERT("tcp_input: active pcb->state != LISTEN", pcb->state != LISTEN);
"""
state.add_constraints(state.se.And(symvar_listen_pcbs_state > 1, symvar_listen_pcbs_state < 10)) # to pass assertions
state.add_constraints(NoReverse(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_listen_pcbs)) == 0x0) # local ip
state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_listen_pcbs)) == 0x560b) # remote ip
state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_listen_pcbs)) == 0xff000002) # so_options, tos, ttl
state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_listen_pcbs)) == 0x0) # padding?
state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 16, symvar_listen_pcbs)) == 0) # next
state.add_constraints(NoReverse(state.se.Extract(8 * 28 - 1, 8 * 24, symvar_listen_pcbs)) == symvar_listen_pcbs_state) # state
# state.add_constraints(NoReverse(state.se.Extract(8 * 32 - 1, 8 * 28, symvar_listen_pcbs)) == 0) # prio?
state.add_constraints(NoReverse(state.se.Extract(8 * 40 - 1, 8 * 32, symvar_listen_pcbs)) == callback_arg) # callback_arg
# state.add_constraints(NoReverse(state.se.Extract(8 * 44 - 1, 8 * 40, symvar_listen_pcbs)) == 7) # local_port
# state.add_constraints(NoReverse(state.se.Extract(8 * 56 - 1, 8 * 48, symvar_listen_pcbs)) == rebased_addr('accept_function')) # accept
state.memory.store(listen_pcbs, state.se.Reverse(symvar_listen_pcbs))


### symbolize tcp_active_pcbs
print "[*] symbolizing tcp_active_pcbs"
"""
gdb-peda$ p (struct tcp_pcb) pcb
$11 = {
  local_ip = {
    addr = 0xea7cbfa8
  },
  remote_ip = {
    addr = 0x560b
  },
  so_options = 0x0,
  tos = 0x0,
  ttl = 0x0,
  next = 0x7fd50530fdf0,
  state = 3931789480,
  prio = 0xb,
  callback_arg = 0x0,
  local_port = 0xfe50,
  remote_port = 0x530,
  flags = 0xd5,
  rcv_nxt = 0xea5a629c,
  rcv_wnd = 0x560b,
  rcv_ann_wnd = 0x0,
  tmr = 0xea7cce00,
  polltmr = 0xb,
  pollinterval = 0x56,
  rtime = 0x0,
  mss = 0xbfa8,
  rttest = 0x560b,
  rtseq = 0x530fe70,
  sa = 0x7fd5,
  sv = 0x0,
  rto = 0x14,
  nrtx = 0x30,
  lastack = 0x1,
  dupacks = 0xce,
  cwnd = 0xea7c,
  ssthresh = 0x560b,
  snd_nxt = 0xea7cce00,
  snd_max = 0x560b,
  snd_wnd = 0x0,
  snd_wl1 = 0x0,
  snd_wl2 = 0x5b10d6e,
  snd_lbb = 0x7fd5,
  acked = 0xd6f,
  snd_buf = 0x5b1,
  snd_queuelen = 0x7fd5,
  unsent = 0x7fd505310700,
  unacked = 0x7fd50530fe80,
  ooseq = 0x560bea5aa751 <tcpip_thread+344>,
  refused_data = 0x0,
  sent = 0x0,
  recv = 0x560bea7c86d8 <memp_memory+4728>,
  connected = 0x69cd72e63fead100,
  accept = 0x0,
  poll = 0x7fd50733c08a <start_thread+218>,
  errf = 0x0,
  keep_idle = 0x5310700,
  persist_cnt = 0x7fd5,
  persist_backoff = 0x0,
  keep_cnt_sent = 0x7
}
"""
pcb = MY_SYMVAR_REGION_BEGIN + 0x16000
state.mem[rebased_addr('tcp_active_pcbs')].uint64_t = pcb
# state.mem[rebased_addr('tcp_active_pcbs') + 8].uint64_t = 0 # terminate with NULL
state.mem[rebased_addr('udp_pcbs')].uint64_t = pcb
symvar_pcb = state.se.BVS('pcb', 0xe0 * 8)
if tcp:
    state.add_constraints(NoReverse(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_pcb)) == 0x0) # local ip
    state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pcb)) == 0x560b) # remote ip
    state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_pcb)) == 0xff000002) # so_options, tos, ttl
    state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_pcb)) == 0x0) # padding?
    state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 16, symvar_pcb)) == 0) # next
    state.add_constraints(NoReverse(state.se.Extract(8 * 28 - 1, 8 * 24, symvar_pcb)) == symvar_listen_pcbs_state) # state
elif udp:
    """
gdb-peda$ p *udp_pcbs
$2 = {
  local_ip = {
    addr = 0x0
  },
  remote_ip = {
    addr = 0x0
  },
  so_options = 0x0,
  tos = 0x0,
  ttl = 0xff,
  next = 0x0, // + 16
  flags = 0x0,
  local_port = 0x7, // + 24
  remote_port = 0x0, // + 26
  recv = 0x55b3c4ce893d <recv_udp>,
  recv_arg = 0x55b3c4f082a0 <memp_memory+3648>
}

gdb-peda$ x/20wx udp_pcbs
0x55b3c4f07580 <memp_memory+288>:   0x00000000  0x00000000  0xff000000  0x00000000
0x55b3c4f07590 <memp_memory+304>:   0x00000000  0x00000000  0x00070000  0x00000000
0x55b3c4f075a0 <memp_memory+320>:   0xc4ce893d  0x000055b3  0xc4f082a0  0x000055b3 // + 32
0x55b3c4f075b0 <memp_memory+336>:   0x00000000  0x00000000  0x00000000  0x00000000
0x55b3c4f075c0 <memp_memory+352>:   0x00000000  0x00000000  0x00000000  0x00000000
    """
    state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pcb)) == 0x0) # remote ip
    state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_pcb)) == 0xff000000) # so_options, tos, ttl
    state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_pcb)) == 0x0) # padding?
    state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 16, symvar_pcb)) == 0) # next
    state.add_constraints(NoReverse(state.se.Extract(8 * 26 - 1, 8 * 24, symvar_pcb)) == 0x7) # local_port
    state.add_constraints(NoReverse(state.se.Extract(8 * 28 - 1, 8 * 26, symvar_pcb)) == 0x0) # remote_port
    state.add_constraints(NoReverse(state.se.Extract(8 * 32 - 1, 8 * 28, symvar_pcb)) == 0x0) # padding?
    # state.add_constraints(NoReverse(state.se.Extract(8 * 40 - 1, 8 * 32, symvar_pcb)) == rebased_addr('recv_udp')) # recv
state.memory.store(pcb, state.se.Reverse(symvar_pcb))

# ### symbolize dns_payload (UNNECCESARY)
# if dns:
#     dns_payload = MY_SYMVAR_REGION_BEGIN + 0x18000
#     dns_payload_ptr = rebased_addr('dns_payload')
#     state.mem[dns_payload_ptr].uint64_t = dns_payload
#     symvar_dns_payload = state.se.BVS('dns_payload', 8 * 1500)
#     state.memory.store(dns_payload, state.se.Reverse(symvar_dns_payload))

### symbolize dns_table
"""MEMO
gdb-peda$ p sizeof(struct dns_table_entry)
$1 = 0x11e
gdb-peda$ p dns_table[0]
$1 = {
  state = 0x2,
  numdns = 0x0,
  tmr = 0x1,
  retries = 0x0,
  seqno = 0x0,
  err = 0x0,
  ttl = 0x0,
  name = "www.google.com", '\000' <repeats 241 times>,
  ipaddr = {
    addr = 0x0
  },
  found = 0x4015a6 <dns_found>,
  arg = 0x0
}
gdb-peda$ x/120wx &dns_table[0]
0x61cba0 <dns_table>: 0x00010002  0x00000000  0x77770000  0x6f672e77
0x61cbb0 <dns_table+16>:  0x656c676f  0x6d6f632e  0x00000000  0x00000000
[...]
0x61cc90 <dns_table+240>: 0x00000000  0x00000000  0x00000000  0x00000000
0x61cca0 <dns_table+256>: 0x00000000  0x00000000  0x00000000  0x15a60000
0x61ccb0 <dns_table+272>: 0x00000040  0x00000000  0x00000000  0x00000000
"""
if dns:
    print "[*] symbolizing dns_table"
    dns_table = rebased_addr('dns_table')
    sizeof_dns_table = sizeof('dns_table')
    sizeof_dns_table_entry = 0x11e
    symvar_dns_table = state.se.BVS('dns_table', 8 * sizeof_dns_table)
    print "[*] sizeof(dns_table) = %#x" % (sizeof_dns_table)
    ### set content of dns_table[0]
    # state.add_constraints(NoReverse(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_dns_table)) == 0x00010002)
    state.add_constraints(NoReverse(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_dns_table)) > 0)
    state.add_constraints(NoReverse(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_dns_table)) == 0)
    state.add_constraints(NoReverse(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_dns_table)) == 0x77770000)
    state.add_constraints(NoReverse(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_dns_table)) == 0x6f672e77)
    state.add_constraints(NoReverse(state.se.Extract(8 * 20 - 1, 8 * 16, symvar_dns_table)) == 0x656c676f)
    state.add_constraints(NoReverse(state.se.Extract(8 * 24 - 1, 8 * 20, symvar_dns_table)) == 0x6d6f632e)
    state.add_constraints(NoReverse(state.se.Extract(8 * 268 - 1, 8 * 24, symvar_dns_table)) == 0)
    state.add_constraints(NoReverse(state.se.Extract(8 * 272 - 1, 8 * 268, symvar_dns_table)) == 0x15a60000) # found
    state.add_constraints(NoReverse(state.se.Extract(8 * 276 - 1, 8 * 272, symvar_dns_table)) == 0x00000040) # found
    state.add_constraints(NoReverse(state.se.Extract(8 * sizeof_dns_table_entry - 1, 8 * 276, symvar_dns_table)) == 0)
    ### spill out dns_table[1] ... dns_table[DNS_TABLE_SIZE]
    state.add_constraints(state.se.Extract(symvar_dns_table.size() - 1, 8 * sizeof_dns_table_entry, symvar_dns_table) == 0)
    ### store symvar
    state.memory.store(dns_table, state.se.Reverse(symvar_dns_table))

    ### debuging
    v = state.se.eval(state.se.Reverse(symvar_dns_table), cast_to=str)
    hexdump.hexdump(v[:sizeof_dns_table_entry])
    for i in range(dns_table, dns_table + sizeof_dns_table_entry, 8):
        try:
            v = state.mem[i].uint64_t.concrete
        except Exception, e:
            print "mem[%#x]: " % i + str(e)
            continue
        if v > 0:
            print "mem[%#x] = %#x" % (i, v)
    # import ipdb; ipdb.set_trace()
    # exit()

### debugging
# dump_regs(state, _exit=False)

if dns:
    print "[*] satisfying calling convention for dns"
    """
    static void    dns_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *addr, u16_t port)
    LWIP_UNUSED_ARG(arg);
    LWIP_UNUSED_ARG(pcb);
    LWIP_UNUSED_ARG(addr);
    LWIP_UNUSED_ARG(port);
    """
    state.regs.rdi = 0        # arg (UNUSED)
    state.regs.rsi = 0        # pcb (UNUSED)
    state.regs.rdx = pbuf_ptr # pbuf
    state.regs.rcx = 0        # addr (UNUSED)
    state.regs.r8 = 0         # port (UNUSED)
# elif ip:
#     """
#     void    tcp_input(struct pbuf *p, struct netif *inp)
#     void    udp_input(struct pbuf *p, struct netif *inp)
#     """
#     state.regs.rdi = pbuf_ptr
#     state.regs.rsi = netif_ptr # inp_ptr
# elif etharp_arp:
#     """
#     void    etharp_arp_input(struct netif *netif, struct eth_addr *ethaddr, struct pbuf *p)
#     """
#     state.regs.rdi = netif_ptr
#     state.regs.rsi = ethaddr_ptr
#     state.regs.rdx = pbuf_ptr

### load initial state to engine (Simulation Manager)
simgr = proj.factory.simgr(state)

### setup avoids
find, avoid = [], []
### pbuf_free() means return of dns_recv()
avoid += [rebased_addr('dns_found')]
avoid += [rebased_addr('pbuf_free')]

### print finds / avoids
print "[*] find = %s" % str(map(lambda x: hex(x), find))
print "[*] avoid = %s" % str(map(lambda x: hex(x), avoid))

### debugging
# proj.hook(0x400000 + 0x1c730, dump_regs, length=4)
# proj.hook(0x400000 + 0x1cecf, dump_regs, length=5)

def step_func(lpg):
    global find, avoid
    if find is not []:
        lpg.stash(filter_func=lambda path: path.addr in find, from_stash='active', to_stash='found')
    if avoid is not []:
        lpg.stash(filter_func=lambda path: path.addr in avoid, from_stash='active', to_stash='avoid')
    lpg.drop(stash='avoid') # memory usage optimization
    return lpg

### explore bugs
simgr.step(step_func=step_func, until=lambda x: len(x.errored) > 0) # explore until error occurs (or active stashes exhausts)
print "[*] explore finished!!"

# if len(simgr.errored) > 0:
#     print "[*] analysis succeeded!"
# else:
#     print "[!] no solutions"
# for i, errored in enumerate(simgr.errored):
#     se = errored.state.plugins['solver_engine']
#     payload_len = se.eval(symvar_pbuf_tot_len)
#     print "errored #{0:d}: pbuf->tot_len: {1:#x} ({1:d})".format(i, payload_len)
#     v = se.eval(se.Reverse(symvar_pbuf_payload), cast_to=str)[:payload_len]
#     print "errored #%d: pbuf->payload:" % (i)
#     hexdump.hexdump(v)

if len(simgr.found) > 0 or len(simgr.errored) > 0:
    plot_trace()
    ### save results
    result = open("result.py", "w")
    result.write("""#!/usr/bin/python
import sys
import pickle
try:
    from scapy.all import *
except ImportError:
    print("[!] `pip install scapy` first! exit.")
    exit(1)

def usage():
    cmd_name = sys.argv[0]
    print("usage: [sudo] %s [PACKET_NO]" % cmd_name)
    print("\\tto preview packet: %s" % cmd_name)
    print("\\tto send packet: sudo %s PACKET_NO" % cmd_name)
    print("")
    print("PACKET_NO of packets are indicated in this script.")
    exit()

def recalc_chksums(p):
    if p.haslayer(IP):
        p[IP].chksum = None # to recalculate checksum
    if p.haslayer(TCP):
        p[TCP].chksum = None # to recalculate checksum
    elif p.haslayer(UDP):
        p[UDP].chksum = None # to recalculate checksum
    fnull = open(os.devnull, 'w')
    fout = sys.stdout
    sys.stdout = fnull # disable output
    p.show2() # recalculate checksum
    sys.stdout = fout # enable output

def eth_type(p):
    eth_type = 0
    if p.haslayer(IP):
        if p[IP].version == 4:
            eth_type = 0x0800 # IPv4
        elif p[IP].version == 6:
            eth_type = 0x0806 # IPv6
    elif p.haslayer(ARP):
        eth_type = 0x0806
    assert(eth_type > 0)
    return eth_type

IS_ROOT = (os.geteuid() == 0)
PACKET_NO = -1
if len(sys.argv) == 2:
    if sys.argv[1] in ["--help", "-h"]:
        usage()
    PACKET_NO = int(sys.argv[1])
if PACKET_NO > 0 and not IS_ROOT:
    print "[!] you must be _root_ to send packet! exit."
    exit(1)
if IS_ROOT and PACKET_NO == -1:
    print "[!] specify packet no"
    usage()
""")
    ###
    num_founds = len(simgr.found)
    for i, found in enumerate(simgr.found):
        print "found #%d: stdout:\n%s" % (i, found.posix.dumps(1))
        print "found #%d: stderr:\n%r" % (i, found.posix.dumps(2))
        if ip:
            v = found.se.eval(symvar_listen_pcbs_state)
            print "found #%d: listen_pcbs->state: %#x (%d)" % (i, v, v)
            print "found #%d: pcb: " % (i)
            v = found.se.eval(found.se.Reverse(symvar_pcb), cast_to=str)
            hexdump.hexdump(v)
        v = found.se.eval(symvar_pbuf_tot_len)
        print "found #%d: pbuf.tot_len: %#x (%d)" % (i, v, v)
        v = found.se.eval(symvar_pbuf_len)
        print "found #%d: pbuf.len: %#x (%d)" % (i, v, v)
        l2_payload_len = v
        v = found.se.eval(symvar_pbuf_type)
        print "found #%d: pbuf.type: %#x (%d)" % (i, v, v)
        v = found.se.eval(symvar_pbuf_ref)
        print "found #%d: pbuf.ref: %#x (%d)" % (i, v, v)
        print "found #%d: pbuf.payload (= L2 Payload): " % (i)
        v = found.se.eval(found.se.Reverse(symvar_pbuf_payload), cast_to=str)
        hexdump.hexdump(v[:l2_payload_len])
        result.write("""\n
### this is Packet #{no:d}
print("[*] ==== [Packet #{no:d}] ====")
print("found #{no:d}: pbuf.payload:")
l2_payload_len = {len:}
v = pickle.loads({dump!r})
if {ip!r}: # is IP packet?
    p = IP(_pkt=v[:l2_payload_len])
elif {etharp!r}: # is Ether packet?
    p = Ether(_pkt=v[:l2_payload_len])
# p[IP].ttl = 64
# p[IP].window = 8192

recalc_chksums(p)
p.show()
b = bytes(p)[:l2_payload_len] # trim unused padding

if IS_ROOT and PACKET_NO == {no:d}: # send mode
    ### write your script here...
    ### send(p) trims padding automically, so I use this one
    if {ip!r}:
        sendp(Ether(dst="11:45:14:11:45:14", type=eth_type(p))/b, iface="tap0")
    if {etharp!r}:
        sendp(b, iface="tap0")
else: # preview mode
    ### write your script here...
    hexdump(b)
    pass
""".format(no=i, dump=pickle.dumps(v), len=l2_payload_len, ip=ip, etharp=etharp_arp))
        print "found #%d: pbuf:" % (i)
        v = memory_dump(found, pbuf_ptr, 0x20)
        hexdump.hexdump(v)
    ###
    for i, errored in enumerate(simgr.errored):
        se = errored.state.plugins['solver_engine']
        payload_len = se.eval(symvar_pbuf_tot_len)
        print "errored #{0:d}: pbuf->tot_len: {1:#x} ({1:d})".format(i, payload_len)
        v = se.eval(se.Reverse(symvar_pbuf_payload), cast_to=str)[:payload_len]
        print "errored #%d: pbuf->payload:" % (i)
        hexdump.hexdump(v)
        result.write("""\n
### this is Packet #{no:d}
print("[*] ==== [Packet #{no:d}] ====")
print("found #{no:d}: pbuf.payload:")
payload_len = {len:}
v = pickle.loads({dump!r})
v = v[:payload_len] # trim unused padding
p = IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=0x1000)/{layer!s}(_pkt=v) # FIXME: dport must be corrected

# recalc_chksums(p)
p.show()
b = bytes(p)[:payload_len]

if IS_ROOT and PACKET_NO == {no:d}: # send mode
    ### write your script here...
    ### send(p) trims padding automically, so I use this one
    if {ip!r}:
        # sendp(Ether(dst="11:45:14:11:45:14", type=eth_type(p))/b, iface="tap0")
        send(p)
else: # preview mode
    ### write your script here...
    hexdump(b)
    pass
""".format(no=(i + num_founds), dump=pickle.dumps(v), len=payload_len, ip=ip, layer="DNS"))
        hexdump.hexdump(v)
    ### the end of iteration
    result.close()
    print ""
    print "[*] attack packets are saved to result.py."

    ### print final result (this can be comment outed)
    print ""
    print "[*] preview of attack packets"
    os.system("python2 result.py")
    os.system("chmod +x result.py")
else:
    print "[!] no outcomes;("
    if len(simgr.avoid) > 0 or len(simgr.deadended) > 0:
        plot_trace()

### you can send generated packets with result.py. enjoy:)