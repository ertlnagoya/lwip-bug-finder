from .template import template

class config(template):
    arch = "arm"
    arch_bits = 32
    ELF_FILE = "./bin/httpsample.elf"
    dump = "bin/httpsample.bin-dump.zip"
    skip_funcs = ['iprintf', 'sys_arch_protect', 'tcp_debug_print', 'DumpHex']
    init_objs = ["dns_table", "dns_payload"]
    find = ['mbed_die', 'assert_printf']
    avoid = ['_Z9dns_foundPKcP7ip_addrPv', 'pbuf_free',
        # 0x1802f634, # '"tcp_input: short packet (%"U16_F" bytes) discarded\n"'
    ]