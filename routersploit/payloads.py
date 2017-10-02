#!/usr/bin/env python

from struct import pack
import inspect
import exploits
from utils import (
    print_success,
    print_status,
    print_info,
    print_error,
    random_text
)

class Payload(exploits.Exploit):
    output = exploits.Option('python', 'Output type: elf/python')
    filepath = exploits.Option('', 'Output file to write')

    def __init__(self):
        self.filepath = "/tmp/{}".format(random_text(8))

        if self.architecture == "armle": 
            self.bigendian = False
            self.header = (
                "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
                "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00"
                "\x00\x80\x00\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
                "\x00\x10\x00\x00"
            )
        elif self.architecture == "mipsbe":
            self.bigendian = True
            self.header = (
                "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\x54\x00\x00\x00\x34"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00"
                "\x00\x40\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xef\x00\x00\x00\x07"
                "\x00\x00\x10\x00"
            )
        elif self.architecture == "mipsle":
            self.bigendian = False
            self.header = (
                "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                "\x02\x00\x08\x00\x01\x00\x00\x00\x54\x00\x40\x00\x34\x00\x00\x00"
                "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
                "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00"
                "\x00\x00\x40\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
                "\x00\x10\x00\x00"
            )

    def run(self):
        print_status("Generating payload")

        args = {}
        for arg in inspect.getargspec(self.generate)[0]:
            if arg in self.exploit_attributes.keys():
                value = getattr(self, arg)
                print_status("{}: {}".format(self.exploit_attributes[arg], value))
                args[arg] = value

        self.generate(**args)

        if self.output == "elf":
            with open(self.filepath, 'w+') as f:
                print_status("Building ELF payload")
                content = self.generate_elf()

                print_success("Saving file {}".format(self.filepath))
                f.write(content)

        elif self.output == "python":
            print_success("Building payload for python")
            content = self.generate_python()
            print_info(content)        

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


