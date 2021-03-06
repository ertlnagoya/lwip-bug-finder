# pylint: skip-file
# pylint: disable-all

import os
import signal
from sys import exit
from time import time, sleep
import re
import subprocess

import hexdump
import struct
import json
import zipfile

from avatar.emulators.s2e import init_s2e_emulator
from avatar.system import System
from avatar.targets.gdbserver_target import *
from avatar.targets.openocd_jig import *
from avatar.targets.openocd_target import *


BIN_FILE = "./bin/httpsample.bin"

"""
/* Linker script to configure memory regions. */
MEMORY
{
  ROM   (rx)  : ORIGIN = 0x00000000, LENGTH = 0x02000000
  BOOT_LOADER (rx) : ORIGIN = 0x18000000, LENGTH = 0x00004000
  SFLASH (rx) : ORIGIN = 0x18004000, LENGTH = 0x07FFC000
  L_TTB (rw)  : ORIGIN = 0x20000000, LENGTH = 0x00004000
  RAM (rwx) : ORIGIN = 0x20020000, LENGTH = 0x00700000
  RAM_NC (rwx) : ORIGIN = 0x20900000, LENGTH = 0x00100000
}
"""

configuration = {
    'output_directory': '/tmp/avatar_gr-peach/',
    'configuration_directory': os.getcwd(),
    "s2e": {
        "emulator_gdb_path": "/home/avatar/projects/gdb-build/gdb/gdb",
        "emulator_gdb_additional_arguments": ["--data-directory=/home/avatar/projects/gdb-build/gdb/data-directory/"],
        's2e_binary': '/home/avatar/projects/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm',
        # 's2e_binary': '/home/avatar/workspace/new-s2e/s2e-build/qemu-release/arm-s2e-softmmu/qemu-system-arm',
        "klee": {
        },
        "plugins": {
            "BaseInstructions": {},
            "Initializer": {},
            "MemoryInterceptor": "",
            "RemoteMemory": {
                "verbose": True,
                "writeBack": True, # FixMe: NOT WORKS
                "listen_address": "localhost:9998",
                "ranges": {
                    "peripherals": {
                        "address": 0xe8000000,
                        "size": 0xffffffff - 0xe8000000,
                        "access": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]
                    },
                    "flash": {
                        "address": 0x20000000, # SRAM (mbed DigitalOut instance comes hore) $sp = 0x20720000, 20020c34
                        "size": 0x20a00000 - 0x20000000,
                        "access": ["read", "write", "execute", "io", "memory", "concrete_value", "concrete_address"]
                    },
                },
            },
        },
        "include": [],
    },

    "qemu_configuration": {
        "gdbserver": False, # 'True' not works
        "halt_processor_on_startup": True,
        "trace_instructions": True,
        "trace_microops": False,
        "append": ["-serial", "tcp::8888,server,nowait", "-S"]
    },

    'machine_configuration': {
        'architecture': 'arm',
        'cpu_model': 'cortex-a9',
        'entry_address': 0x18005d78, # Reset_Handler
        "memory_map": [
            {
                "size": 0x08000000,
                "name": "rom",
                "file": BIN_FILE,
                "map": [
                    {"address": 0x18000000, # Flash Memory (ROM) (BIN_FILE goes here)
                     "type": "code",
                     "permissions": "rwx"}
                ]
            },
        ],
    },

    "avatar_configuration": {
        "target_gdb_address": "tcp:localhost:3333",
        "target_gdb_additional_arguments": ["--data-directory=/home/avatar/projects/gdb-build/gdb/data-directory/"],
        "target_gdb_path": "/home/avatar/projects/gdb-build/gdb/gdb",
    },
    'openocd_configuration': {
        'config_file': 'renesas_gr-peach.cfg'
    }
    }


def get_symbol_addr(file_name, symbol):
    out = subprocess.check_output("readelf -s %s" % file_name, shell=True, universal_newlines=True)
    for line in out.split('\n'):
        line += "$"
        if line.find(" " + symbol + "$") >= 0:
            # print(line)
            # m = re.match(r'\d+: ([0-9a-f]+)\s+\d+ (\w+)\D+\d+ ([^\s@]+)', line)
            m = re.match(r'^\s+\d+\: ([0-9a-f]+)\s', line)
            return int("0x" + m.group(1), 16)
    return -1 # ERROR

def read_pointer_value(t, elf_file, symbol_name, symbol_addr=-1):
    if symbol_addr < 0:
        symbol_addr = get_symbol_addr(elf_file, symbol_name)
        if symbol_addr < 0:
            print("[!] symbol '%s' not found" % symbol_name)
            return (None, None)
    symbol = t.read_untyped_memory(symbol_addr, 4)
    symbol = struct.unpack("<I", symbol)[0]
    print("\t*%s (addr=%#x) = %#x" % (symbol_name, symbol_addr, symbol))
    return (symbol_addr, symbol)

REGISTERS = [
    'r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11',
    'r12', 'sp', 'lr', 'pc', 'cpsr'
]

def get_regs(debuggable):
    regs = []
    print("==== [dump registers] ====")
    for r in REGISTERS:
        print("$%s = %#x" % (r, debuggable.get_register(r)))
        regs.append(debuggable.get_register(r))
    print("==========================")
    return regs

def set_regs(debuggable, regs):
    assert(len(regs) == len(REGISTERS))
    for i in range(len(regs)):
        # print("%s <= %#x" % (REGISTERS[i], regs[i]))
        debuggable.set_register(REGISTERS[i], regs[i])

def read_memory(debuggable, address, size):
    return debuggable._gdb_interface._gdb.sync_cmd(["-data-read-memory", "0x%x" % address, "x", "4", "1", "%d" % (size / 4)], "done")['memory'][0]['data']

def do_dump(debuggable, address, size):
    begin = address
    end = address + size
    file_name = 'memory-{begin:x}-{end:x}'.format(begin=begin, end=end)
    data = read_memory(debuggable, address, size)
    ret = b''
    for x in data:
        ret += struct.pack('<I', int(x, 16))
    with open(file_name, 'wb') as f:
        f.write(ret)
    return (begin, end, file_name)

def memory_dump(t, bin_name, areas):
    DUMP_JSON = 'dump.json'

    dumps = []
    if bin_name == "" or len(areas) == 0:
        usage()
        return
    zip_name = bin_name + "-dump.zip"
    for x in areas:
        begin, size = x
        print("mem: {:#x} +{:#x}".format(begin, size))
        dumps.append(do_dump(t, begin, size))
    print(json.dumps(dumps))
    with open(DUMP_JSON, 'w') as f:
        f.write(json.dumps(dumps))

    print("zip name: {}".format(zip_name))
    zf = zipfile.ZipFile(zip_name, mode='w', compression=zipfile.ZIP_DEFLATED)
    for d in dumps:
        file_name = d[2]
        zf.write(file_name)
        os.unlink(file_name)
    zf.write(DUMP_JSON)
    os.unlink(DUMP_JSON)
    zf.close()

    print('[*] memory dump done! Go on your analysis!')

def main():

    if not os.path.exists(BIN_FILE):
        print("[!] BIN_FILE = %s is not exists!" % BIN_FILE)
        exit()

    elf_file = BIN_FILE.replace(r".bin", r".elf")

    # main_addr = get_symbol_addr(elf_file, "http_main_task")
    main_addr = get_symbol_addr(elf_file, "_Z15HTTPServerStarti")
    print("[*] main = %#x" % (main_addr))

    print("[*] Starting the GR-PEACH demo")

    print("[+] Resetting target via openocd")
    hwmon = OpenocdJig(configuration)
    cmd = OpenocdTarget(hwmon.get_telnet_jigsock())
    cmd.raw_cmd("reset halt")

    print("[+] Initilializing avatar")
    ava = System(configuration, init_s2e_emulator, init_gdbserver_target)
    ava.init()
    ava.start()
    t = ava.get_target()
    e = ava.get_emulator()

    print("[+] Running initilization procedures on the target")
    print("\tEthernet Cable has connected?")
    print("first break point = %#x" % main_addr)
    main_bkt = t.set_breakpoint(main_addr)
    t.cont()
    main_bkt.wait()

    # ### for experiment
    # print("[*] waiting for mbed_die")
    # mbed_die_addr = get_symbol_addr(elf_file, "mbed_die")
    # print("[*] mbed_die = %#x" % (mbed_die_addr))
    # mbed_die_bkt = t.set_breakpoint(mbed_die_addr)
    # t.cont()
    # mbed_die_bkt.wait()
    # print("[*] reached to mbed_die()")

    print("[+] Target finished initilization procedures")
    read_pointer_value(t, elf_file, "tcp_active_pcbs")
    read_pointer_value(t, elf_file, "tcp_listen_pcbs")
    a, v = read_pointer_value(t, elf_file, "netif_list")
    a, v = read_pointer_value(t, elf_file, "*netif_list", v)
    read_pointer_value(t, elf_file, "ram")
    read_pointer_value(t, elf_file, "ram_end")

    print("[+] copying target memory")
    """
    K_atc% nm httpsample.elf| grep dns_table
    2003acac b dns_table
    """
    start = time.time()
    try:
        # ret = t.read_untyped_memory(0x18000000, 0x20000000 - 0x18000000) # TOO SLOW
        # t.read_untyped_memory(0x18000000, 0x1000) # for experiment
        # read_memory(t, 0x18000000, 0x1000) # for experiment
        memory_dump(t, BIN_FILE, [(0x20030000, 0x20050000 - 0x20030000)]) # < 5 min
    except Exception as e:
        print(e)
        import ipdb; ipdb.set_trace()
    print("[+] memory read time: %f sec" % (time.time() - start))
    # import ipdb; ipdb.set_trace()

    #Further analyses code goes here
    print("[+] analysis phase")

    e.stop() # important
    t.stop() # important

if __name__ == '__main__':
    main()
    print("[*] finished")
    # os.system("kill " + str(os.getpid()))
    exit()
