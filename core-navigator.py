#!/usr/bin/env python
import mmap
import struct
import sys

import elf64


#
# https://bugzilla.redhat.com/show_bug.cgi?id=1371380
#
# If producing core dump with gcore, do:
#
#    (gdb) shell echo 0x37 >/proc/PID/coredump_filter
#


def find_unique_note(notes, name, type):
    note, = [note
             for note in notes
             if note.name == name and note.type == type]
    return note


def find_unique_auxv(auxvs, type):
    auxv, = [auxv
             for auxv in auxvs
             if auxv.type == type]
    return auxv.value


def ptr2off(phdrs, ptr):
    for phdr in phdrs:
        if phdr.p_vaddr <= ptr < phdr.p_vaddr + phdr.p_memsz:
            return ptr - phdr.p_vaddr + phdr.p_offset
    raise Exception()


def find_unique_phdr(phdrs, p_type):
    phdr, = [phdr
             for phdr in phdrs
             if phdr.p_type == p_type]
    return phdr


def find_unique_dt(dts, d_tag):
    dt, = [dt
           for dt in dts
           if dt.d_tag == d_tag]
    return dt


def get_link_map_l_name(fp, phdrs, lm):
    fp.seek(ptr2off(phdrs, lm) + 8)
    l_name_ptr, = struct.unpack('Q', fp.read(8))
    l_name_off = ptr2off(phdrs, l_name_ptr)
    return elf64.read_sz(fp, l_name_off, -1)


def get_link_map_l_next(fp, phdrs, lm):
    fp.seek(ptr2off(phdrs, lm) + 24)
    next_link_map_ptr, = struct.unpack('Q', fp.read(8))
    return next_link_map_ptr


def navigate(fp, ptr):
    ptr_str = struct.pack('Q', ptr)
    ehdr = elf64.Elf64_Ehdr.read(fp)
    fp.seek(ehdr.e_phoff)
    phdrs = elf64.Elf64_Phdr.read_all(
        fp, ehdr.e_phnum, ehdr.e_phentsize)
    fp.seek(ehdr.e_shoff)
    shdrs = elf64.Elf64_Shdr.read_all(
        fp, ehdr.e_shnum, ehdr.e_shentsize)
    phdr_notes = find_unique_phdr(phdrs, elf64.PT_NOTE)
    fp.seek(phdr_notes.p_offset)
    notes = elf64.Elf64_Note.read_all(fp, phdr_notes.p_filesz)
    auxv_note = find_unique_note(notes, "CORE", elf64.NT_AUXV)
    fp.seek(auxv_note.descoff)
    auxvs = elf64.Elf64_Auxv.read_all(fp, auxv_note.descsz)
    phdr_ptr = find_unique_auxv(auxvs, elf64.AT_PHDR)
    fp.seek(ptr2off(phdrs, phdr_ptr))
    main_phdrs = elf64.Elf64_Phdr.read_all(
        fp,
        find_unique_auxv(auxvs, elf64.AT_PHNUM),
        find_unique_auxv(auxvs, elf64.AT_PHENT))
    main_phdr_pt = find_unique_phdr(main_phdrs, elf64.PT_PHDR)
    if phdr_ptr != main_phdr_pt.p_vaddr:
        raise Exception()
    main_phdr_dynamic = find_unique_phdr(main_phdrs, elf64.PT_DYNAMIC)
    fp.seek(ptr2off(phdrs, main_phdr_dynamic.p_vaddr))
    main_dts = elf64.Elf64_Dyn.read_all(fp, main_phdr_dynamic.p_memsz)
    main_dt_debug = find_unique_dt(main_dts, elf64.DT_DEBUG)
    fp.seek(ptr2off(phdrs, main_dt_debug.d_val + 8))
    link_map_ptr, = struct.unpack('Q', fp.read(8))
    while link_map_ptr != 0:
        print 'file=%s' % get_link_map_l_name(fp, phdrs, link_map_ptr)
        link_map_ptr = get_link_map_l_next(fp, phdrs, link_map_ptr)
    for phdr in phdrs:
        pos = phdr.p_offset
        end = phdr.p_offset + phdr.p_memsz
        while pos < end:
            pos = fp.find(ptr_str, pos, end)
            if pos == -1:
                break
            addr = phdr.p_vaddr + (pos - phdr.p_offset)
            print 'offset=0x%x ptr=0x%x' % (pos, addr)
            pos += 1


path, ptr = sys.argv[1:]
ptr = int(ptr, 0)
with open(path) as fp:
    mm = mmap.mmap(fp.fileno(), 0, access=mmap.ACCESS_READ)
    try:
        navigate(mm, ptr)
    finally:
        mm.close()
