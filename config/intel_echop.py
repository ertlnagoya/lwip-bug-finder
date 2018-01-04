from .template import template

class config(template):
    arch = "intel"
    arch_bits = 64
    ELF_FILE = "./bin/echop-STABLE-1_3_0"
    skip_funcs = []
    init_objs = ["dns_table"]
    find = []
    ### pbuf_free() means return of dns_recv()]
    avoid = ['dns_found', 'pbuf_free']
