import struct

import bindata


class link_map(object):
    FORMAT = 'QQQQQ'
    SIZEOF = struct.calcsize(FORMAT)

    def __init__(self, s):
        (self.l_addr,
         self.l_name,
         self.l_ld,
         self.l_next,
         self.l_prev,
         ) = struct.unpack(link_map.FORMAT, s)

    @staticmethod
    def read(fp):
        s = fp.read(link_map.SIZEOF)
        return link_map(s)

    @staticmethod
    def read_all(fp, ptr2off):
        lms = []
        ptr, = struct.unpack('Q', fp.read(8))
        while ptr != 0:
            fp.seek(ptr2off(ptr))
            lm = link_map.read(fp)
            lms.append(lm)
            ptr = lm.l_next
        return lms

    def read_name(self, fp, ptr2off):
        return bindata.read_sz(fp, ptr2off(self.l_name), -1)
