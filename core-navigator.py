#!/usr/bin/env python
import mmap
import struct
import sys

import bindata
import elf64
import link64


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


def navigate(fp, ptr):
    ptr_str = struct.pack('Q', ptr)
    ehdr = elf64.Elf64_Ehdr.read(fp)
    fp.seek(ehdr.e_phoff)
    phdrs = elf64.Elf64_Phdr.read_all(
        fp, ehdr.e_phnum, ehdr.e_phentsize)

    def local_ptr2off(ptr):
        return ptr2off(phdrs, ptr)

    phdr_notes = find_unique_phdr(phdrs, elf64.PT_NOTE)
    fp.seek(phdr_notes.p_offset)
    notes = elf64.Elf64_Note.read_all(fp, phdr_notes.p_filesz)
    auxv_note = find_unique_note(notes, "CORE", elf64.NT_AUXV)
    fp.seek(auxv_note.descoff)
    auxvs = elf64.Elf64_Auxv.read_all(fp, auxv_note.descsz)
    phdr_ptr = find_unique_auxv(auxvs, elf64.AT_PHDR)
    fp.seek(local_ptr2off(phdr_ptr))
    main_phdrs = elf64.Elf64_Phdr.read_all(
        fp,
        find_unique_auxv(auxvs, elf64.AT_PHNUM),
        find_unique_auxv(auxvs, elf64.AT_PHENT))
    main_phdr_pt = find_unique_phdr(main_phdrs, elf64.PT_PHDR)
    if phdr_ptr != main_phdr_pt.p_vaddr:
        raise Exception()
    main_phdr_dynamic = find_unique_phdr(main_phdrs, elf64.PT_DYNAMIC)
    fp.seek(local_ptr2off(main_phdr_dynamic.p_vaddr))
    main_dts = elf64.Elf64_Dyn.read_all(fp, main_phdr_dynamic.p_memsz)
    main_dt_debug = find_unique_dt(main_dts, elf64.DT_DEBUG)
    fp.seek(local_ptr2off(main_dt_debug.d_val + 8))
    lms = link64.link_map.read_all(fp, local_ptr2off)
    for lm in lms:
        lib_name = lm.read_name(fp, local_ptr2off)
        print 'file=%s' % lib_name
        if len(lib_name) == 0:
            l_addr = lm.l_addr
        else:
            l_addr = 0
        fp.seek(local_ptr2off(lm.l_ld))
        lib_dts = elf64.Elf64_Dyn.read_all(fp)
        lib_strtab = find_unique_dt(lib_dts, elf64.DT_STRTAB)
        lib_strtab_off = local_ptr2off(l_addr + lib_strtab.d_val)
        lib_symtab = find_unique_dt(lib_dts, elf64.DT_SYMTAB)
        lib_symsize = find_unique_dt(lib_dts, elf64.DT_SYMENT).d_val
        lib_symcount = (lib_strtab.d_val - lib_symtab.d_val) / lib_symsize
        fp.seek(local_ptr2off(l_addr + lib_symtab.d_val))
        syms = elf64.Elf64_Sym.read_all(fp, lib_symcount, lib_symsize)
        for sym in syms:
            sym_name_off = lib_strtab_off + sym.st_name
            print '  symbol=%s' % bindata.read_sz(fp, sym_name_off, -1)
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
