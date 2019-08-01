#!/usr/bin/python
import sys


class ReadFile:
    file = None
    filename = ''
    offset = 0

    def __init__(self, filename, offset):
        self.filename = filename
        self.offset = offset
        self.file = open(self.filename, 'rb')
        self.file.seek(self.offset)

    def read(self, length):
        return self.file.read(length)

    def close(self):
        self.file.close()

    def read_hash(self, length):
        bs = bytes()
        ob = bytes()
        for i in range(length):
            b = self.read(1)
            bs = b + bs
            ob = ob + b
        return bs, ob

    def read_int(self, length):
        result = 0
        ob = bytes()
        for i in range(length):
            b = self.read(1)
            result = b[0] << (8 * i) | result
            ob = ob + b
        return result, ob

    def read_compact_size(self):
        b, bs = self.read_int(1)
        ob = bytes()
        if b < 253:
            size = b
            ob = ob + bs
        elif b == 253:
            b, bs = self.read_int(2)
            size = b
            ob = ob + bs
            if size < 253:
                raise Exception('non-canonical read_compact_size()')
        elif b == 254:
            b, bs = self.read_int(4)
            size = b
            ob = ob + bs
            if size < 0x10000:
                raise Exception('non-canonical read_compact_size()')
        else:
            b, bs = self.read_int(8)
            size = b
            ob = ob + bs
            if size < 0x100000000:
                raise Exception('non-canonical read_compact_size()')

        if size > sys.maxsize:
            raise Exception('read_compact_size(): size too large')
        return size, ob
