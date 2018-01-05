#!/usr/bin/python2
# encoding: utf-8
from argparse import ArgumentParser
import angr #the main framework
import claripy #the solver engine
try:
    import emoviz # execution trace visualizer
except ImportError as e:
    print e
    print "[!] cannot load emoviz module. missing emoviz.py in current directory. exit."
    exit(1)
import os, sys, signal
import importlib
import pickle, json
import hashlib
import zipfile
import struct
import hexdump
import time, datetime

###
start_time = time.time() # start measure

### angr's routine
ANGR_LOG = "angr.log"
angr.manager.l.setLevel("DEBUG")
logging = angr.manager.logging
log_handler = logging.FileHandler(ANGR_LOG, mode='w')
log_handler.setLevel(logging.DEBUG)
log_handler.setFormatter(logging.Formatter('%(levelname)-7s | %(asctime)-23s | %(name)-8s | %(message)s'))
angr.manager.l.addHandler(log_handler)

### argparse routine
desc = u'{0} [Args] [Options]\nDetailed options -h or --help'.format(__file__) # error message
parser = ArgumentParser(description=desc)
parser.add_argument(
        '-c', '--config',
        type=str,          # 受け取る値の型を指定する
        dest='config', # 保存先変数名
        required=True,     # 必須項目
        help='configuration file (target file path, find/avoid, ...)' # --help時に表示する文
    )
parser.add_argument(
        '-f', '--start_func',
        type=str,          # 受け取る値の型を指定する
        dest='start_func', # 保存先変数名
        required=True,     # 必須項目
        help='function name to start analysis' # --help時に表示する文
    )
parser.add_argument(
        '-b', '--constrained_blocks',
        type=str,          # 受け取る値の型を指定する
        dest='constrained_blocks', # 保存先変数名
        required=False,     # 必須項目
        help='constrained blocks. e.g. -b \'-b 1,2\'' # --help時に表示する文
    )
parser.add_argument(
        '-d', '--dfs',
        action='store_true', # store_trueでdestにTrueがはいる(store_falseもある)
        dest='dfs'
    )
parser.add_argument(
        '-s', '--segv',
        action='store_true', # store_trueでdestにTrueがはいる(store_falseもある)
        dest='check_segv'
    )
args = parser.parse_args()

### ==================================================================
TRACE_SAVE_DIR = "./trace/"
os.system("if [ ! -d %s ]; then mkdir %s; fi" % (TRACE_SAVE_DIR, TRACE_SAVE_DIR))
os.system("rm -f %s[a-zA-Z]*-[0-9]*.{png,dot,txt,log}" % (TRACE_SAVE_DIR))
def plot_trace():
    global proj, state

    def helper(proj, state, dot_file, transition_file, plain_file=""):
        ev = emoviz.emoviz(proj)
        ev.add(state)
        ev.save_dot(dot_file)
        ev.save_png(dot_file)
        ev.save_transitions(transition_file)
        if plain_file:
            ev.save_plain(plain_file)

    for (i, act) in enumerate(simgr.active):
        dot_file = TRACE_SAVE_DIR + "active-%d.dot" % i
        transition_file = TRACE_SAVE_DIR + "transition_active-%d" % i
        helper(proj, act.state, dot_file, transition_file
            # plain_file=TRACE_SAVE_DIR + "active-%d.txt" % i
            )
        if i >= 15: break
    if hasattr(simgr, "found"):
        for (i, fnd) in enumerate(simgr.found):
            dot_file = TRACE_SAVE_DIR + "found-%d.dot" % i
            transition_file = TRACE_SAVE_DIR + "transition_found-%d" % i
            helper(proj, fnd.state, dot_file, transition_file)
    if hasattr(simgr, "avoid"):
        for (i, avd) in enumerate(simgr.avoid):
            dot_file = TRACE_SAVE_DIR + "avoid-%d.dot" % i
            transition_file = TRACE_SAVE_DIR + "transition_avoid-%d" % i
            helper(proj, avd.state, dot_file, transition_file
                # plain_file=TRACE_SAVE_DIR + "avoid-%d.txt" % i
                )
            if i > 5: break
    if hasattr(simgr, "deferred"):
        for (i, x) in enumerate(simgr.deferred):
            dot_file = TRACE_SAVE_DIR + "deferred-%d.dot" % i
            transition_file = TRACE_SAVE_DIR + "transition_deferred-%d" % i
            helper(proj, x.state, dot_file, transition_file
                # plain_file=TRACE_SAVE_DIR + "avoid-%d.txt" % i
                )
            if i >= 9: break
    for (i, ddd) in enumerate(simgr.deadended):
        dot_file = TRACE_SAVE_DIR + "deadended-%d.dot" % i
        transition_file = TRACE_SAVE_DIR + "transition_deadended-%d" % i
        helper(proj, ddd.state, dot_file, transition_file)
        if i > 5: break
    for (i, err) in enumerate(simgr.errored):
        dot_file = TRACE_SAVE_DIR + "errored-%d.dot" % i
        transition_file = TRACE_SAVE_DIR + "transition_errored-%d" % i
        helper(proj, err.state, dot_file, transition_file)
        if i >= 14: break

def signal_handler(signal, frame):
    print('[*] received SIGNAL')
    plot_trace()
    exit(1)
signal.signal(signal.SIGINT, signal_handler) # Ctrl+C
### ==================================================================

def check_file_consistency(file_name, filesum):
    if filesum:
        with open(ELF_FILE, 'rb') as f:
            s = hashlib.md5(f.read()).hexdigest()
        return s == filesum
    else:
        return True

init_memory = {}
def load_memory_dump(file_name):
    global memory_dump
    print "[*] loading memory dump: %s" % file_name
    zf = zipfile.ZipFile(file_name)
    print "\tzip file contains %s" % str(zf.namelist())
    dump = {}
    with zf.open('dump.json') as f:
        dump = json.load(f)
    for d in dump:
        begin, end, file_name = d
        print "\tfile: %s" % file_name
        print "\tmem: %#x - %#x" % (begin, end)
        with zf.open(file_name) as f:
            init_memory[(begin, end)] = f.read()

def read_memory_dump(addr, size):
    global init_memory
    for k, v in init_memory.items():
        begin, end = k
        if begin <= addr and (addr + size) <= end:
            offset = addr - begin
            ret = v[offset:offset+size]
            r = size % 4
            if r > 0:
                ret += '\0' * (4 - r)
            return ret
    raise Exception("unmapped addr, size: %#x, %#x" % (addr, size))

def conv_to_address(_list):
    ret = []
    for x in _list:
        if isinstance(x, int):
            ret.append(x)
        elif isinstance(x, str):
            ret.append(rebased_addr(x))
    return ret

def memory_dump(state, begin, length):
    ret = ""
    for i in range(0, length):
        val = state.solver.eval(state.memory.load(begin + i, 1))
        ret += chr(val)
    return ret

def split_str(str, num):
    ret = []
    for i in range(num):
        ret.append(str[i::num])
    ret = ["".join(i) for i in zip(*ret)]
    rem = len(str) % num  # remainder of zip()
    if rem:
        ret.append(str[-rem:])
    return ret

def find_symbol(x):
    global proj
    sym = proj.loader.find_symbol(x)
    if sym is None:
        raise Exception("symbol '%s' is not found" % (x))
    return sym

def sizeof(symbol_name):
    global info
    return info.symbols[symbol_name].size

def dhms(t):
    orig = t
    t = int(t)
    d = t / (24 * 3600)
    t -= d * 24 * 3600
    h = t / 3600
    t -= h * 3600
    m = t / 60
    t -= m * 60
    s = t % 60
    return "{:02d}:{:02d}:{:02d}:{:02d} ({:.3f}s)".format(d, h, m, s, orig)

def proc_cmdline():
    with open("/proc/self/cmdline") as f:
        ret = f.read().strip('\0').split('\0')
    return ret

def usage():
    print "usage: %s START_FUNC_NAME" % (sys.argv[0])
    exit(1)


### === helper functions ===
rebased_addr = lambda x: find_symbol(x).rebased_addr
relative_addr = lambda x: find_symbol(x).relative_addr
NoReverse = lambda x: x
BigEndian = lambda x: state.se.Reverse(x)
LittleEndian = lambda x: x


### load configuration
config = importlib.import_module('config.' + args.config).config


### analysis start function
START_FUNC = args.start_func
if START_FUNC not in ['tcp_input', 'udp_input', 'etharp_arp_input', 'dns_recv']:
    print "[!] invalid function name"
    exit(1)


### choose blocks to constrain
CONSTRAINED_BLOCKS = [1, 2] # 0, 1, 2, 3
if args.constrained_blocks:
    CONSTRAINED_BLOCKS = [int(x) for x in args.constrained_blocks.split(',')]
else:
    CONSTRAINED_BLOCKS = []
print "[*] CONSTRAINED_BLOCKS = %s" % (str(CONSTRAINED_BLOCKS))


### explore options given by cmdline
DEPTH_FIRST = args.dfs # DFS Option
CHECK_SEGV = args.check_segv


### load binary
ELF_FILE = config.elf()
proj = angr.Project(ELF_FILE, load_options={'auto_load_libs': False})
start_addr = rebased_addr(START_FUNC)
print "[*] analysis start: %#x" % start_addr


### helper boolean
dns = ('dns_' in START_FUNC)
tcp = ('tcp_' in START_FUNC)
udp = ('udp_' in START_FUNC)
etharp_arp = ('etharp_arp_' in START_FUNC)
ip = tcp or udp


### pbuf_ptr
if config.arch == "intel":
    MY_SYMVAR_REGION_BEGIN = 0x20000000
elif config.arch == "arm":
    MY_SYMVAR_REGION_BEGIN = 0x40000000
MY_SYMVAR_REGION_LENGTH = 0x1000000
pbuf_ptr = MY_SYMVAR_REGION_BEGIN


### create initial state
if START_FUNC == "dns_recv":
    print "[*] satisfying calling convention for dns_recv"
    """
    dns_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, ip_addr_t *addr, u16_t port)
    """
    state = proj.factory.call_state(start_addr, 0, 0, pbuf_ptr, 0, 0)
elif START_FUNC == "tcp_input":
    print "[*] satisfying calling convention for tcp_input"
    """
    tcp_input(struct pbuf *p, struct netif *inp)
    """
    state = proj.factory.call_state(start_addr, pbuf_ptr, 0)
else:
    print "[!] unknown initial state"
    exit(1)


### add inspector
def outbound_access_constriant(state, read_addr):
    arch_name = state.arch.name
    if arch_name == "AMD64":
        return state.solver.And(
            read_addr > 0x00620000, # pbuf->payload: 0x61f7a2
            read_addr < 0x015ae000,
            )
    elif arch_name == "ARMEL": # Not Good Idea (there're no segv in mbed)
        return state.solver.And(
            read_addr > 0x2003d000, # pbuf->payload: 0x2003b8de
            read_addr < 0x20080000,
            )
    else:
        raise Exception("Unhandled arch_name")

def is_outbound_read_access(state):
    read_addr = state.inspect.mem_read_address
    return state.solver.satisfiable(extra_constraints=[outbound_access_constriant(state, read_addr)])

segv_found = False
def check_segv(state):
    global simgr, segv_found
    if segv_found:
        return
    read_addr = state.inspect.mem_read_address
    if not hasattr(read_addr, 'symbolic'):
        return
    if read_addr.symbolic:
        print '>> Read', repr(state.inspect.mem_read_expr)[:240], 'from', repr(state.inspect.mem_read_address)[:240]
        print "[*] satisfiable: %s" % repr(is_outbound_read_access(state))
        if is_outbound_read_access(state):
            try:
                segv_found = True
                print "[*] found memory access violation"
                # state.add_constraints(state.solver.And(
                # read_addr > 0x00620000,
                # read_addr < 0x015ae000,
                # )) # NOT WORKS (lifetime of `state` is short?)
                print "[*] pbuf->payload:"
                payload_len = state.solver.eval(symvar_pbuf_tot_len)
                v = state.solver.eval(state.solver.Reverse(symvar_pbuf_payload), cast_to=str)[:payload_len]
                hexdump.hexdump(v)
                simgr.found.append(state)
                for active in simgr.active:
                    active.add_constraints(outbound_access_constriant(active, read_addr))
                # import ipdb; ipdb.set_trace()
            except Exception as e:
                print "[!] Exception: ", e
                import ipdb; ipdb.set_trace()

if CHECK_SEGV:
    print "[*] Option enabled: check SEGV on memory access"
    state.inspect.b("mem_read", when=angr.BP_BEFORE, action=check_segv)


### map new region for my symbolic variables
"""memo for echop
gdb-peda$ vmmap
Start              End                Perm  Name
0x00400000         0x00418000         r-xp  /home/tomori/lwip/lwip-bug-finder/bin/echop-STABLE-1_3_0
0x00617000         0x00618000         r--p  /home/tomori/lwip/lwip-bug-finder/bin/echop-STABLE-1_3_0
0x00618000         0x00619000         rw-p  /home/tomori/lwip/lwip-bug-finder/bin/echop-STABLE-1_3_0
0x00619000         0x00620000         rw-p  mapped
0x015ae000         0x015cf000         rw-p  [heap]
"""
state.memory.mem.map_region(MY_SYMVAR_REGION_BEGIN, MY_SYMVAR_REGION_LENGTH, 0b011) # begin, len, permissions(rw-p)


### change options
if dns:
    state.options.add("STRICT_PAGE_ACCESS") # to handle SEGV
    # state.mem[0x00900].uint32_t = 1145 # to check mode; => 'write-miss'
# import ipdb; ipdb.set_trace()


### load preprocessed data
print "[*] loading preprocessed data"
from preprocess import Info, Symbol
INFO_FILE = ELF_FILE + ".info"
try:
    with open(INFO_FILE) as f:
        info = pickle.load(f)
    if hasattr(info, "filesum"):
        print("[*] checking file consistency...")
        if check_file_consistency(ELF_FILE, info.filesum) is False:
            raise Exception("[!] target file is NOT the one pre-processed.")
        print("\tOK")
    else:
        print("[!] info file does not have file hash. should preprocess")
        time.sleep(3) # thinking time
except IOError as e:
    print e
    print "[!] run `./preprocess.py %s` first" % (ELF_FILE)
    exit(1)


### load memory dump
if len(config.init_objs) > 0:
    print "[*] loading memory dump"
    if hasattr(config, "dump") and config.dump:
        DUMP_FILE = config.dump
    else:
        DUMP_FILE = ELF_FILE + "-dump.zip"
    try:
        load_memory_dump(DUMP_FILE)
    except IOError as e:
        print e
        print "[!] there're no memory dumps"
        print "[!] run `source ./memory-dump.py` in gdb first" % ()
        exit()
else:
    print("[*] there're no initialized objects. skip loading memory dump")


### disables function calls. and sets return value 0
def handle_ret_0(state):
    arch_name = state.arch.name
    if arch_name == "AMD64":
        state.regs.rax = 0
    elif arch_name == "ARMEL":
        state.regs.r0 = 0
    else:
        raise Exception("[!] Unknown Arch name '%s'" % (arch_name))

### start ipdb
def handle_start_ipdb(state):
    import ipdb; ipdb.set_trace()

### hooks function calls
try:
    ### nop function x() calls
    funcs = []
    if hasattr(config, "skip_funcs"):
        funcs += config.skip_funcs
    else:
        raise Exception("config.skip_funcs is not defined")
    if len(funcs) > 0:
        print("[*] hooking functions...")
        if config.arch == "intel":
            hook_length = 5
            hook_offset = 0x400000  # dirty hack
        else:
            hook_length = 4
            hook_offset = 0
    for func_name in funcs:
        if func_name in info.call:
            for x in info.call[func_name]:
                print("\thooking %s (reladdr=%#x, size=%#x)" % (func_name, x, hook_length))
                proj.hook(hook_offset + x, handle_ret_0, length=hook_length)
        else:
            print "[!] info.call has not key '%s'" % func_name
            exit(1)
        """buggy. not implemented correctly
        # addr = rebased_addr(func_name)
        # size = sizeof(func_name)
        # print("\thooking %s (addr=%#x, size=%#x)" % (func_name, addr, size))
        # proj.hook(addr, handle_ret_0, length=size)
        """
    # for func_name in ["pbuf_copy_partial"]:
    #     proj.hook(rebased_addr(func_name), handle_start_ipdb, length=sizeof(func_name))
    if config.arch == "arm":
        ### hook libc functions in mbed with angr's SimProcedures
        for symname in angr.SIM_PROCEDURES['libc'].keys():
            print("\thooking libc '%s'" % (symname))
            proj.hook_symbol(symname, angr.SIM_PROCEDURES['libc'][symname])
except Exception as e:
    print e
    import ipdb; ipdb.set_trace()

# proj.hook(0x1802f548, handle_start_ipdb, length=4)

### enable debug flag
if config.arch == "intel":
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
if config.arch == "arm":
    pbuf_payload = 0x2003b8de
else:
    pbuf_payload = 0x61f7a2  # pbuf is located in section "mapped"
if config.arch_bits == 64:
    pbuf_next = pbuf_ptr + 0x0
    pbuf_payload_ptr = pbuf_ptr + 0x8
    pbuf_tot_len = pbuf_ptr + 0x10
    pbuf_len = pbuf_ptr + 0x12
    pbuf_type = pbuf_ptr + 0x14
    pbuf_flags = pbuf_ptr + 0x15
    pbuf_ref = pbuf_ptr + 0x16
    # state.mem[pbuf_next].uint64_t = 0 # NULL
    state.mem[pbuf_payload_ptr].uint64_t = pbuf_payload # => p->payload == pbuf_payload
elif config.arch_bits == 32:
    """
    pbuf:
    2003b8a4 | 00 00 00 00 DE B8 03 20  3E 00 3E 00 00 00 01 00  |  ....... >.>.....
    pbuf->payload (addr=0x2003b8de):
    2003b8de | 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |  ................
    2003b8ee | 06 67 6F 6F 67 6C 65 03  63 6F 6D 00 00 01 00 01  |  .google.com.....
    2003b8fe | 03 77 77 77 06 67 6F 6F  67 6C 65 03 63 6F 6D 00  |  .www.google.com.
    2003b90e | 00 00 00 00 00 00 00 00  00 00 00 00 00 00        |  ..............
    """
    pbuf_next = pbuf_ptr + 0
    pbuf_payload_ptr = pbuf_ptr + 4
    pbuf_tot_len = pbuf_ptr + 8
    pbuf_len = pbuf_ptr + 10  # u16_t
    pbuf_type = pbuf_ptr + 12  # u8_t
    pbuf_flags = pbuf_ptr + 13  # u8_t
    pbuf_ref = pbuf_ptr + 14  # u16_t
    # state.mem[pbuf_next].uint32_t = 0 # NULL
    state.mem[pbuf_payload_ptr].uint32_t = pbuf_payload # => p->payload == pbuf_payload
else:
    raise Exception("could not layout pbuf")

### symbolize pbuf.tot_len
symvar_pbuf_tot_len = state.se.BVS('pbuf_tot_len', 16) # u16_t
if dns:
    state.add_constraints(symvar_pbuf_tot_len == 0x3e) # IMPORTANT; for dns_recv
else:
    state.add_constraints(symvar_pbuf_tot_len > 0)
state.memory.store(pbuf_tot_len, state.se.Reverse(symvar_pbuf_tot_len))

### symbolize pbuf.len
symvar_pbuf_len = state.se.BVS('pbuf_len', 16) # u16_t
state.add_constraints(symvar_pbuf_tot_len == symvar_pbuf_len)
ip_min_len = 20
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
if dns:
    state.add_constraints(symvar_pbuf_type == 0x0)
else:
    # state.add_constraints(state.se.Or(symvar_pbuf_type == 0x0, symvar_pbuf_type == 0x3)) # RAM = 0, REF = 2, POOL = 3
    pass ### should not constrain pbuf->type in pbuf_header (called by tcp_input)
state.memory.store(pbuf_type, state.se.Reverse(symvar_pbuf_type))

### symbolize pbuf.ref
symvar_pbuf_ref = state.se.BVS('pbuf_ref', 16)
state.add_constraints(symvar_pbuf_ref == 1) # reference count
state.memory.store(pbuf_ref, state.se.Reverse(symvar_pbuf_ref))

### add constraints for a packet
L2_PAYLOAD_MAX_LEN = 1500 # 1518 (max Ether frame size) - 14 (address) - 4 (FCS)
symvar_pbuf_payload = state.se.BVS('pbuf_payload', L2_PAYLOAD_MAX_LEN * 8)
tcp_header_offset = 5 * 4 * 8
if dns:
    """
    gdb-peda$ x/12wx p->payload
    0x61f7a2 <memp_memory+8930>:    0x80810000  0xffff0100  0x00000000  0x77777703
    0x61f7b2 <memp_memory+8946>:    0x6f6f6706  0x03656c67  0x006d6f63  0x01000100
    0x61f7c2 <memp_memory+8962>:    0x77777703  0x6f6f6706  0x03656c67  0x006d6f63
    0x61f7d2 <memp_memory+8978>:    0x01000100  0x00000000  0x007f0400  0x000c0100
    """
    ### block 0
    if 0 in CONSTRAINED_BLOCKS:
        print("[*] block 0 has constrained!")
        state.add_constraints(LittleEndian(state.se.Extract(8 * 4 - 1, 8 * 0, symvar_pbuf_payload)) == 0x80810000)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pbuf_payload)) == 0x01000100) # Answer RRs = 0x01
        ## state.add_constraints(LittleEndian(state.se.Extract(8 * 8 - 1, 8 * 4, symvar_pbuf_payload)) == 0xff000100) # Answer RRs = 0xff
        state.add_constraints(LittleEndian(state.se.Extract(8 * 12 - 1, 8 * 8, symvar_pbuf_payload)) == 0)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 16 - 1, 8 * 12, symvar_pbuf_payload)) == 0x77777703)

    ### block 1
    if 1 in CONSTRAINED_BLOCKS:
        print("[*] block 1 has constrained!")
        state.add_constraints(LittleEndian(state.se.Extract(8 * 20 - 1, 8 * 16, symvar_pbuf_payload)) == 0x6f6f6706)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 24 - 1, 8 * 20, symvar_pbuf_payload)) == 0x03656c67)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 28 - 1, 8 * 24, symvar_pbuf_payload)) == 0x006d6f63)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 32 - 1, 8 * 28, symvar_pbuf_payload)) == 0x01000100)

    ### block 2
    if 2 in CONSTRAINED_BLOCKS:
        print("[*] block 2 has constrained!")
        state.add_constraints(LittleEndian(state.se.Extract(8 * 36 - 1, 8 * 32, symvar_pbuf_payload)) == 0x77777703)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 40 - 1, 8 * 36, symvar_pbuf_payload)) == 0x6f6f6706)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 44 - 1, 8 * 40, symvar_pbuf_payload)) == 0x03656c67)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 48 - 1, 8 * 44, symvar_pbuf_payload)) == 0x006d6f63)

    ### block 3
    if 3 in CONSTRAINED_BLOCKS:
        print("[*] block 3 has constrained!")
        state.add_constraints(LittleEndian(state.se.Extract(8 * 52 - 1, 8 * 48, symvar_pbuf_payload)) == 0x01000100)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 56 - 1, 8 * 52, symvar_pbuf_payload)) == 0)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 60 - 1, 8 * 56, symvar_pbuf_payload)) == 0x007f0400)
        ## state.add_constraints(LittleEndian(state.se.Extract(8 * 60 - 1, 8 * 56, symvar_pbuf_payload)) == 0x007fffff)
        state.add_constraints(LittleEndian(state.se.Extract(8 * 64 - 1, 8 * 60, symvar_pbuf_payload)) == 0x000c0100)
elif tcp:
    state.add_constraints(state.se.Extract(7, 0, symvar_pbuf_payload) == 0x45) # ip version & ip header size (IPHL)
    state.add_constraints(state.se.Reverse(state.se.Extract(31, 16, symvar_pbuf_payload)) == symvar_pbuf_len) # Total Length in IP header
    state.add_constraints(state.se.Extract(32 * 2 + 7, 32 * 2 + 0, symvar_pbuf_payload) > 0) # TTL
    symvar_ip_proto = state.se.Extract(32 * 2 + 15, 32 * 2 + 8, symvar_pbuf_payload)
    if tcp:
        state.add_constraints(symvar_ip_proto == 6) # ip proto (TCP = 6, UDP = 0x11)
    elif udp:
        state.add_constraints(symvar_ip_proto == 0x11) # ip proto (TCP = 6, UDP = 0x11)
    else:
        state.add_constraints(state.se.Or(symvar_ip_proto == 6, symvar_ip_proto == 0x11)) # ip proto (TCP = 6, UDP = 0x11)
    state.add_constraints(state.se.Reverse(state.se.Extract(32 * 3 + 31, 32 * 3 + 0, symvar_pbuf_payload)) == 0xc0a80001) # ip src (192.168.0.1)
    state.add_constraints(state.se.Reverse(state.se.Extract(32 * 4 + 31, 32 * 4 + 0, symvar_pbuf_payload)) == 0xc0a80002) # ip dest (192.168.0.2)
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x3f, tcp_header_offset + 0x20, symvar_pbuf_payload)) > 0) # seqno
    state.add_constraints(state.se.Reverse(state.solver.Extract(tcp_header_offset + 0x5f, tcp_header_offset + 0x40, symvar_pbuf_payload)) > 0) # ackno
    if tcp:
        symvar_tcp_dataofs = state.solver.Extract(tcp_header_offset + 96 + 7, tcp_header_offset + 96 + 4, symvar_pbuf_payload)
        state.add_constraints(state.se.And(symvar_tcp_dataofs >= 5, symvar_tcp_dataofs <= 15)) # tcp length
    pass
### load packet to engine
state.memory.store(pbuf_payload, state.se.Reverse(symvar_pbuf_payload))

print "[*] pbuf->payload"
v = state.se.eval(state.se.Reverse(symvar_pbuf_payload), cast_to=str)
hexdump.hexdump(v[:0x80])

### load initialized object values
print "[*] loading initialized objects to engine:"
for objname in config.init_objs:
    begin = rebased_addr(objname)
    print "\tloading %s ... (addr = %#x)" % (objname, begin)
    objval = read_memory_dump(begin, sizeof(objname))
    for i, sv in enumerate(split_str(objval, 4)):
        v = struct.unpack('<I', sv)[0]
        state.mem[begin + i * 4].uint32_t = v

#### check if initialized correctry
if dns:
    print("dns_table:")
    v = state.se.eval(state.memory.load(rebased_addr("dns_table"), 0x120), cast_to=str)
    hexdump.hexdump(v)


### load initial state to engine (Simulation Manager)
simgr = proj.factory.simgr(state)

### use exploration techniques
THREADING = True
THREADING = False
if THREADING:
    print "[*] simgr.use_technique: Threading enabled"
    simgr.use_technique(angr.exploration_techniques.Threading(6)) # NOTE: pypy & python2 causes segmentation fault
elif DEPTH_FIRST:
    print "[*] simgr.use_technique: DFS enabled"
    simgr.use_technique(angr.exploration_techniques.DFS())
else:
    print "[*] Default exploration mode"

### setup find/avoid
find, avoid = conv_to_address(config.find), conv_to_address(config.avoid)

### print finds / avoids
print "[*] find = %s" % str(map(lambda x: hex(x), find))
print "[*] avoid = %s" % str(map(lambda x: hex(x), avoid))

def step_func(lpg):
    global find, avoid, THREADING, DEPTH_FIRST
    # time.sleep(0.2)
    if THREADING:
        if find is not []:
            lpg.stash(filter_func=lambda path: path.addr in find, from_stash='active', to_stash='found')
        lpg.stash(filter_func=lambda path: path.addr in avoid, from_stash='active', to_stash='avoid')
    else:
        if find is not []:
            lpg.stash(filter_func=lambda path: path.addr in find, from_stash='active', to_stash='found')
        lpg.stash(filter_func=lambda path: path.addr in avoid, from_stash='active', to_stash='avoid')

    for s in lpg.errored:
        if 'Unsupported CCall' in s.error.message:  # ex) 'Unsupported CCall armg_calculate_flags_nzcv'
            print("[!] Unhandled error: " + s.error.message)
            import ipdb; ipdb.set_trace()
            # plot_trace()
            exit(1)

    lpg.drop(stash='avoid') # memory usage optimization

    # if THREADING:
    #     print "[*] len(lpg.active) = %d, len(lpg.threadlocal) = %d" % (len(lpg.active), len(lpg.threadlocal))
    #     if len(lpg.active) == 0 and len(lpg.threadlocal) > 0:
    #         lpg.active.append(lpg.threadlocal.pop())
    if DEPTH_FIRST:
        print "[*] len(lpg.active) = %d, len(lpg.deferred) = %d" % (len(lpg.active), len(lpg.deferred))
        if len(lpg.active) == 0 and len(lpg.deferred) > 0:
            lpg.active.append(lpg.deferred.pop())
    return lpg

def until_func(lpg):
    if len(lpg.found) > 0:
        return True
    if len(lpg.errored) > 0:
        return True
    if len(lpg.active) == 0: # No Meaning
        print "[*] out of active stashes"
        if hasattr('threadlocal', lpg):
            return len(lpg.threadlocal) == 0
        if hasattr('deferred', lpg):
            return len(lpg.deferred) == 0


### explore bugs
time.sleep(5)
assert(avoid is not [])
simgr.step(step_func=step_func, until=until_func) # explore until error occurs (or active stashes exhausts)
print "[*] explore finished!!"
# exit(1) # uncomment to utilize vmprof

print "[*] mode:"
print "\tTHREADING = %r" % (THREADING)
print "\tDEPTH_FIRST = %r" % (DEPTH_FIRST)

RESULT_PY = "result.py"
RESULT_TXT = "result.txt"
print "[*] saving result to %s" % (RESULT_TXT)
ftxt = open(RESULT_TXT, 'w')
fout = sys.stdout
sys.stdout = ftxt # redirect to a file
FOUND_RESULT = len(simgr.found) > 0 or len(simgr.errored) > 0
if FOUND_RESULT:
    plot_trace()

    if dns:
        layer = "DNS"
    elif tcp or udp:
        layer = "IP"
    else:
        layer = "Raw"

    ### save results
    result = open(RESULT_PY, "w")
    result.write("""#!/usr/bin/python2
import sys
import pickle
try:
    from scapy.all import *
except ImportError:
    print("[!] `pip install scapy` first! exit.")
    exit(1)

### ==================================================================
def usage():
    cmd_name = sys.argv[0]
    print("usage: [sudo] %s [IFACE] [PACKET_NO]" % cmd_name)
    print("\\tto preview packet: %s" % cmd_name)
    print("\\tto send packet with eth0: sudo %s eth0 PACKET_NO" % cmd_name)
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
if len(sys.argv) == 1:
    pass
elif len(sys.argv) < 3:
    if sys.argv[1] in ["--help", "-h"]:
        usage()
else:
    IFACE = sys.argv[1]
    PACKET_NO = int(sys.argv[2])
if PACKET_NO > 0 and not IS_ROOT:
    print("[!] you must be _root_ to send packet! exit.")
    exit(1)
if IS_ROOT and PACKET_NO == -1:
    print("[!] specify packet no")
    usage()
### ==================================================================
""")
    ###
    try:
        num_founds = len(simgr.found)
        for i, found in enumerate(simgr.found):
            print "found #%d: pc: %#x" % (i, found.addr)
            print "found #%d: stdout:\n%s" % (i, found.posix.dumps(1))
            print "found #%d: stderr:\n%r" % (i, found.posix.dumps(2))
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
            v = found.se.eval(found.memory.load(pbuf_payload, L2_PAYLOAD_MAX_LEN), cast_to=str)[:l2_payload_len]
            hexdump.hexdump(v[:l2_payload_len])
            if dns:
                anrrs = ord(v[6]) * 0x100 + ord(v[7])
                print "found #{0:d}: DNS: Answer RRs: {1:d} ({1:#x})".format(i, anrrs)
            result.write("""\n
### this is Packet #{no:d}
print("[*] ==== [Packet #{no:d}] ====")
print("found #{no:d}: pbuf.payload:")
payload_len = {len:}
v = pickle.loads(b{dump!r})
v = v[:payload_len] # trim unused payload
if {layer} == DNS:
    p = IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=0x1000)/Raw(v) # FIXME: dport must be corrected
else:
    p = {layer}(_pkt=v)
if p.haslayer(IP):
    p[IP].ttl = 128
if p.haslayer(TCP):
    # p[TCP].dport = 80
    pass

recalc_chksums(p)
try:
    p.show2()
except Exception as e:
    print(e)
    print("p.show() errored.")
b = bytes(p)[:payload_len]

if IS_ROOT and PACKET_NO == {no:d}: # send mode
    ### write your script here...
    ### send(p) trims padding automatically, so I use this one
    sendp(Ether(dst="11:45:14:11:45:14", type=eth_type(p))/b, iface=IFACE)
    send(p)
else: # preview mode
    ### write your script here...
    hexdump(b)
    pass
""".format(no=i, dump=pickle.dumps(v), len=l2_payload_len, layer=layer))
            print "found #%d: pbuf:" % (i)
            v = memory_dump(found, pbuf_ptr, 0x20)
            hexdump.hexdump(v)
    ###
        for i, errored in enumerate(simgr.errored):
            se = errored.state.plugins['solver_engine']
            posix = errored.state.plugins['posix']
            memory = errored.state.plugins['memory']
            print "errored #%d: error.reason: %s" % (i, errored.error.reason)
            print "errored #%d: error.addr: %#x" % (i, errored.error.addr)
            print "errored #%d: error.ins_addr: %#x" % (i, errored.error.ins_addr)
            print "errored #%d: stdout:\n%s" % (i, posix.dumps(1))
            print "errored #%d: stderr:\n%r" % (i, posix.dumps(2))
            payload_len = se.eval(symvar_pbuf_tot_len)
            print "errored #{0:d}: pbuf->tot_len: {1:#x} ({1:d})".format(i, payload_len)
            v = se.eval(se.Reverse(symvar_pbuf_payload), cast_to=str)
            # v = se.eval(memory.load(pbuf_payload, L2_PAYLOAD_MAX_LEN), cast_to=str)
            print "errored #%d: pbuf->payload:" % (i)
            hexdump.hexdump(v[:payload_len])
            if dns:
                anrrs = ord(v[6]) * 0x100 + ord(v[7])
                print "errored #{0:d}: DNS: Answer RRs: ({1:#x}) {1:d}".format(i, anrrs)
            result.write("""\n
### this is Packet #{no:d}
print("[*] ==== [Packet #{no:d}] ====")
print("found #{no:d}: pbuf.payload:")
payload_len = {len:}
v = pickle.loads(b{dump!r})
# v = bytes(v, encoding='ascii')
v = v[:payload_len] # trim unused payload
# p = IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=0x1000)/{layer!s}(_pkt=v) # FIXME: dport must be corrected
p = IP(src="8.8.8.8", dst="192.168.0.2")/UDP(sport=53, dport=0x1000)/Raw(v) # FIXME: dport must be corrected

recalc_chksums(p)
try:
    p.show2()
except Exception as e:
    print(e)
    print("p.show() errored.")
b = bytes(p)[:payload_len]

if IS_ROOT and PACKET_NO == {no:d}: # send mode
    ### write your script here...
    ### send(p) trims padding automatically, so I use this one
    sendp(Ether(dst="00:02:f7:f0:00:00", type=eth_type(p))/b, iface=IFACE)
    send(p)
else: # preview mode
    ### write your script here...
    hexdump(b)
    pass
""".format(no=(i + num_founds), dump=pickle.dumps(v), len=payload_len, layer="DNS"))
    except Exception as e:
        result.close()
        sys.stdout = fout # re-enable stdout
        ftxt.close()
        ###
        print "[!] Exception Occurred:"
        print e
        print "'type c<Enter>' to continue"
        import ipdb; ipdb.set_trace()

    ### the end of iteration
    result.close()
    print ""
    print "[*] attack packets are saved to %s." % (RESULT_PY)
else: # if FOUND_RESULT
    print "[!] no outcomes;("
    if len(simgr.avoid) > 0 or len(simgr.deadended) > 0:
        plot_trace()
sys.stdout = fout # re-enable stdout
ftxt.close()
### print final result if exists (this can be comment outed)
if FOUND_RESULT:
    os.system("if [ -e {py} ]; then (echo; echo '[*] preview of attack packets'; python2 {py}) >> {txt}; fi".format(py=RESULT_PY, txt=RESULT_TXT))
os.system("cat %s" % (RESULT_TXT)) # print solver script message

if FOUND_RESULT:
    ### end measurement
    run_time = time.time() - start_time
    cpu_time = time.clock() # < python 3.3

    ### save files to output directory
    OUTPUT_DIR = "./output-last/"
    os.system("if [ ! -d {dir} ]; then mkdir {dir}; else rm -rf {dir}/*; fi".format(dir=OUTPUT_DIR))
    os.system("cp {_from!s} {_to!s}".format(_from=sys.argv[0], _to=OUTPUT_DIR)) # this solver script
    os.system("chmod -w {_to!s}/{_from!s}".format(_from=sys.argv[0], _to=OUTPUT_DIR)) # this solver script
    for x in [RESULT_TXT, RESULT_PY, ANGR_LOG, TRACE_SAVE_DIR]:
        os.system("mv {_from!s} {_to!s}".format(_from=x, _to=OUTPUT_DIR))
    print "[*] output files are saved to {!s}".format(OUTPUT_DIR)

    ### write README
    README = OUTPUT_DIR + "README.txt"
    with open(README, "w") as f:
        f.write("""README: About this output directory\n
Host:
    {host}

Executed date:
    {date} (UTC)

Command line:
    % {cmd!s}

Run time (Hour:Min:Sec):
    {run_time}, cpu: {cpu_time}

Run result:
    ./{txt}

Attacker script:
    ./{py}

angr's debug log:
    ./{log}

Trace (state history):
    ./trace
""".format(host=os.uname()[1], date=datetime.datetime.utcfromtimestamp(start_time).strftime("%Y/%m/%d %H:%M:%S"),
        cmd=' '.join(proc_cmdline()), run_time=dhms(run_time), cpu_time=dhms(cpu_time),
        txt=RESULT_TXT, py=RESULT_PY, log=ANGR_LOG))

# import ipdb; ipdb.set_trace()

### you can send generated packets with result.py. enjoy:)