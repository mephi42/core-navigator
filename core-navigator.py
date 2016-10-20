#!/usr/bin/env python
import mmap
import struct
import sys

import elf64


def get_strtab_shdr(shdrs):
    strtab_shdr, = [shdr
                    for shdr in shdrs
                    if shdr.sh_type == elf64.SHT_STRTAB]
    return strtab_shdr


def read_notes(fp, shdrs):
    notes = []
    for shdr in shdrs:
        if shdr.sh_type == elf64.SHT_NOTE:
            fp.seek(shdr.sh_offset)
            notes.extend(elf64.Elf64_Note.read_all(fp, shdr.sh_size))
    return notes


def get_auxv_note(notes):
    auxv_note, = [note
                  for note in notes
                  if note.name == "CORE" and note.type == elf64.NT_AUXV]
    return auxv_note


def get_ldso_base(auxvs):
    base_auxv, = [auxv
                  for auxv in auxvs
                  if auxv.type == elf64.AT_BASE]
    return base_auxv.value


def ptr2off(shdrs, ptr):
    for shdr in shdrs:
        if shdr.sh_addr <= ptr < shdr.sh_addr + shdr.sh_size:
            return ptr - shdr.sh_addr + shdr.sh_offset
    raise Exception()


def get_dynamic_phdr(phdrs):
    dynamic_phdr, = [phdr
                     for phdr in phdrs
                     if phdr.p_type == elf64.PT_DYNAMIC]
    return dynamic_phdr


def navigate(fp, ptr):
    ptr_str = struct.pack('Q', ptr)
    ehdr = elf64.Elf64_Ehdr.read(fp)
    fp.seek(ehdr.e_shoff)
    shdrs = elf64.Elf64_Shdr.read_all(
        fp, ehdr.e_shnum, ehdr.e_shentsize)
    strtab_shdr = get_strtab_shdr(shdrs)
    notes = read_notes(fp, shdrs)
    auxv_note = get_auxv_note(notes)
    fp.seek(auxv_note.descoff)
    auxvs = elf64.Elf64_Auxv.read_all(fp, auxv_note.descsz)
    ldso_ptr = get_ldso_base(auxvs)
    ldso_offset = ptr2off(shdrs, ldso_ptr)
    fp.seek(ldso_offset)
    ldso_ehdr = elf64.Elf64_Ehdr.read(fp)
    fp.seek(ldso_offset + ldso_ehdr.e_phoff)
    ldso_phdrs = elf64.Elf64_Phdr.read_all(
        fp, ldso_ehdr.e_phnum, ldso_ehdr.e_phentsize)
    ldso_dynamic_phdr = get_dynamic_phdr(ldso_phdrs)
    fp.seek(ptr2off(shdrs, ldso_ptr + ldso_dynamic_phdr.p_vaddr))
    ldso_dts = elf64.Elf64_Dyn.read_all(fp, ldso_dynamic_phdr.p_memsz)
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
