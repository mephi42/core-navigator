def read_sz(fp, sz_start, sz_end):
    sz_end = fp.find('\0', sz_start, sz_end)
    if sz_end == -1:
        raise Exception()
    fp.seek(sz_start)
    return fp.read(sz_end - sz_start)
