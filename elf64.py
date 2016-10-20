import struct


# https://www.uclibc.org/docs/elf-64-gen.pdf
# http://articles.manugarg.com/aboutelfauxiliaryvectors


class Elf64_Ehdr(object):
    FORMAT = '16sHHIQQQIHHHHHH'
    SIZEOF = struct.calcsize(FORMAT)

    def __init__(self, s):
        (self.e_ident,
         self.e_type,
         self.e_machine,
         self.e_version,
         self.e_entry,
         self.e_phoff,
         self.e_shoff,
         self.e_flags,
         self.e_ehsize,
         self.e_phentsize,
         self.e_phnum,
         self.e_shentsize,
         self.e_shnum,
         self.e_shstrndx,
         ) = struct.unpack(Elf64_Ehdr.FORMAT, s)

    @staticmethod
    def read(fp):
        return Elf64_Ehdr(fp.read(Elf64_Ehdr.SIZEOF))


SHT_NULL = 0
SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_HASH = 5
SHT_DYNAMIC = 6
SHT_NOTE = 7


def read_sz(fp, sz_start, sz_end):
    sz_end = fp.find('\0', sz_start, sz_end)
    if sz_end == -1:
        raise Exception()
    fp.seek(sz_start)
    return fp.read(sz_end - sz_start)


class Elf64_Shdr(object):
    FORMAT = 'IIQQQQIIQQ'
    SIZEOF = struct.calcsize(FORMAT)

    def __init__(self, s):
        (self.sh_name,
         self.sh_type,
         self.sh_flags,
         self.sh_addr,
         self.sh_offset,
         self.sh_size,
         self.sh_link,
         self.sh_info,
         self.sh_addralign,
         self.sh_entsize
         ) = struct.unpack(Elf64_Shdr.FORMAT, s)

    @staticmethod
    def read_all(fp, count, size):
        shdrs = []
        i = 0
        while i < count:
            shdrs.append(Elf64_Shdr(fp.read(size)))
            i += 1
        return shdrs

    def read_name(self, fp, strtab_shdr):
        return read_sz(
            fp,
            strtab_shdr.sh_offset + self.sh_name,
            strtab_shdr.sh_offset + strtab_shdr.sh_size)


def strip_nul(s):
    end = s.find('\0')
    if end == -1:
        return s
    else:
        return s[:end]


def pad4(n):
    return ((n - 1) | 3) + 1


NT_PRSTATUS = 1
NT_PRFPREG = 2
NT_PRPSINFO = 3
NT_TASKSTRUCT = 4
NT_AUXV = 6


class Elf64_Note(object):
    FORMAT = 'III'
    SIZEOF = struct.calcsize(FORMAT)

    def __init__(self, fp):
        (namesz,
         self.descsz,
         self.type
         ) = struct.unpack(Elf64_Note.FORMAT,
                           fp.read(Elf64_Note.SIZEOF))
        nameoff = fp.tell()
        self.name = strip_nul(fp.read(namesz))
        self.descoff = pad4(nameoff + namesz)
        note_end = pad4(self.descoff + self.descsz)
        fp.seek(note_end)

    @staticmethod
    def read_all(fp, length):
        notes = []
        end = fp.tell() + length
        while fp.tell() < end:
            notes.append(Elf64_Note(fp))
        return notes


AT_NULL = 0
AT_IGNORE = 1
AT_EXECFD = 2
AT_PHDR = 3
AT_PHENT = 4
AT_PHNUM = 5
AT_PAGESZ = 6
AT_BASE = 7
AT_FLAGS = 8
AT_ENTRY = 9
AT_NOTELF = 10
AT_UID = 11
AT_EUID = 12
AT_GID = 13
AT_EGID = 14
AT_PLATFORM = 15
AT_HWCAP = 16
AT_CLKTCK = 17
AT_SECURE = 23
AT_BASE_PLATFORM = 24
AT_RANDOM = 25
AT_HWCAP2 = 26
AT_EXECFN = 31


class Elf64_Auxv(object):
    FORMAT = 'QQ'
    SIZEOF = struct.calcsize(FORMAT)

    def __init__(self, fp):
        (self.type,
         self.value,
         ) = struct.unpack(Elf64_Auxv.FORMAT,
                           fp.read(Elf64_Auxv.SIZEOF))

    @staticmethod
    def read_all(fp, length):
        auxvs = []
        pos = fp.tell()
        end = pos + length
        while pos + Elf64_Auxv.SIZEOF <= end:
            auxv = Elf64_Auxv(fp)
            pos += Elf64_Auxv.SIZEOF
            if auxv.type == AT_NULL:
                return auxvs
            auxvs.append(auxv)
        raise Exception()


PT_NULL = 0
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_NOTE = 4
PT_SHLIB = 5
PT_PHDR = 6
PT_LOOS = 0x60000000
PT_HIOS = 0x6FFFFFFF
PT_LOPROC = 0x70000000
PT_HIPROC = 0x7FFFFFFF


class Elf64_Phdr(object):
    FORMAT = 'IIQQQQQQ'
    SIZEOF = struct.calcsize(FORMAT)

    def __init__(self, s):
        (self.p_type,
         self.p_flags,
         self.p_offset,
         self.p_vaddr,
         self.p_paddr,
         self.p_filesz,
         self.p_memsz,
         self.p_align,
         ) = struct.unpack(Elf64_Phdr.FORMAT, s)

    @staticmethod
    def read_all(fp, count, size):
        phdrs = []
        i = 0
        while i < count:
            phdrs.append(Elf64_Phdr(fp.read(size)))
            i += 1
        return phdrs


DT_NULL = 0
DT_NEEDED = 1
DT_PLTRELSZ = 2
DT_PLTGOT = 3
DT_HASH = 4
DT_STRTAB = 5
DT_SYMTAB = 6
DT_RELA = 7
DT_RELASZ = 8
DT_RELAENT = 9
DT_STRSZ = 10
DT_SYMENT = 11
DT_INIT = 12
DT_FINI = 13
DT_SONAME = 14
DT_RPATH = 15
DT_SYMBOLIC = 16
DT_REL = 17
DT_RELSZ = 18
DT_RELENT = 19
DT_PLTREL = 20
DT_DEBUG = 21
DT_TEXTREL = 22
DT_JMPREL = 23
DT_BIND_NOW = 24
DT_INIT_ARRAY = 25
DT_FINI_ARRAY = 26
DT_INIT_ARRAYSZ = 27
DT_FINI_ARRAYSZ = 28


class Elf64_Dyn(object):
    FORMAT = 'QQ'
    SIZEOF = struct.calcsize(FORMAT)

    def __init__(self, s):
        (self.d_tag,
         self.d_val,
         ) = struct.unpack(Elf64_Dyn.FORMAT, s)

    @staticmethod
    def read_all(fp, length):
        dts = []
        pos = fp.tell()
        end = pos + length
        while pos + Elf64_Dyn.SIZEOF <= end:
            dt = Elf64_Dyn(fp.read(Elf64_Dyn.SIZEOF))
            pos += Elf64_Dyn.SIZEOF
            if dt.d_tag == DT_NULL:
                return dts
            dts.append(dt)
        raise Exception()
