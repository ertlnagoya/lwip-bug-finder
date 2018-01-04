from .template import template

class config(template):
    arch = "arm"
    arch_bits = 32
    ELF_FILE = "./bin/httpsample.elf"
    dump = "bin/httpsample.bin-dump.zip"
    skip_funcs = ['iprintf', 'sys_arch_protect', 'DumpHex']
    init_objs = ["dns_table", "dns_payload"]
    find = ['mbed_die']
    avoid = ['_Z9dns_foundPKcP7ip_addrPv', 'pbuf_free']