import struct


# https://www.uclibc.org/docs/elf-64-gen.pdf


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
    def read_all(fp):
        sections = []
        while True:
            s = fp.read(Elf64_Shdr.SIZEOF)
            if len(s) == 0:
                return sections
            sections.append(Elf64_Shdr(s))

    def read_sz(self, fp, offset):
        sz_start = self.sh_offset + offset
        sz_end = fp.find('\0', sz_start, self.sh_offset + self.sh_size)
        if sz_end == -1:
            raise Exception()
        fp.seek(sz_start)
        return fp.read(sz_end - sz_start)

    def read_name(self, fp, strtab_shdr):
        return strtab_shdr.read_sz(fp, self.sh_name)


def strip_nul(s):
    end = s.find('\0')
    if end == -1:
        return s
    else:
        return s[:end]


def pad4(n):
    return ((n - 1) | 3) + 1


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
