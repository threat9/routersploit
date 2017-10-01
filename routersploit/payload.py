#!/usr/bin/env python

from struct import pack


class Payload(object):
    header = None

    def convert_ip(self, addr):
        res = ""
        for i in addr.split("."):
            res += chr(int(i))
        return res

    def convert_port(self, p):
        res = "%.4x" % int(p)
        return res.decode('hex')

    def generate_elf(self):
        elf = self.header + self.payload

        if self.bigendian:
            p_filesz = pack(">L", len(elf))
            p_memsz = pack(">L", len(elf) + len(self.payload))
        else:
            p_filesz = pack("<L", len(elf))
            p_memsz = pack("<L", len(elf) + len(self.payload))

        content = elf[:0x44] + p_filesz + p_memsz + elf[0x4c:]
        return content

    def generate_python(self):
        res = "payload = (\n    \""
        for idx, x in enumerate(self.payload):
            if idx % 15 == 0 and idx != 0:
                res += "\"\n    \""

            res += "\\x%02x" % ord(x)
        res += "\"\n)"
        return res

