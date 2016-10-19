#!/usr/bin/env python
import mmap
import struct
import sys

import elf64


def navigate(fp, ptr):
    ptr_str = struct.pack('Q', ptr)
    ehdr = elf64.Elf64_Ehdr.read(fp)
    fp.seek(ehdr.e_shoff)
    shdrs = elf64.Elf64_Shdr.read_all(fp)
    strtab_shdr, = [shdr
                    for shdr in shdrs
                    if shdr.sh_type == elf64.SHT_STRTAB]
    shdr_index = -1
    for shdr in shdrs:
        shdr_index += 1
        name = shdr.read_name(fp, strtab_shdr)
        if shdr.sh_type != elf64.SHT_PROGBITS:
            continue
        pos = shdr.sh_offset
        end = shdr.sh_offset + shdr.sh_size
        while pos < end:
            pos = fp.find(ptr_str, pos, end)
            if pos == -1:
                break
            addr = shdr.sh_addr + (pos - shdr.sh_offset)
            print '%s[%d]' % (name, shdr_index), hex(pos), hex(addr)
            pos += 1


path, ptr = sys.argv[1:]
ptr = int(ptr, 0)
with open(path) as fp:
    mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        navigate(mm, ptr)
    finally:
        mm.close()
