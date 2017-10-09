#!/usr/bin/env python

from struct import pack
import exploits
from utils import (
    print_success,
    print_error,
    print_status,
    print_info,
)

ARCH_ELF_HEADERS = {
    "armle": ("\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
              "\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00"
              "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
              "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00"
              "\x00\x80\x00\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
              "\x00\x10\x00\x00"),
    "mipsbe": ("\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\x54\x00\x00\x00\x34"
               "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00"
               "\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00"
               "\x00\x40\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xef\x00\x00\x00\x07"
               "\x00\x00\x10\x00"),
    "mipsle": ("\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
               "\x02\x00\x08\x00\x01\x00\x00\x00\x54\x00\x40\x00\x34\x00\x00\x00"
               "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
               "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00"
               "\x00\x00\x40\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
               "\x00\x10\x00\x00")
}


class Payload(exploits.Exploit):
    def __init__(self):
        if self.architecture == "generic":
            self.bigendian = None
            self.header = None
        else:
            if self.architecture == "armle":
                self.bigendian = False
                self.header = ARCH_ELF_HEADERS['armle']
            elif self.architecture == "mipsbe":
                self.bigendian = True
                self.header = ARCH_ELF_HEADERS['mipsbe']
            elif self.architecture == "mipsle":
                self.bigendian = False
                self.header = ARCH_ELF_HEADERS['mipsle']

    def validate_params(self):
        for option in self.exploit_attributes.keys():
            if not getattr(self, option):
                print_error("Invalid value for {}".format(option))
                return None
        return True
        
    def run(self):
        if not self.validate_params():
            return
        
        print_status("Generating payload")
        data = self.generate()

        if self.architecture == "generic":
            print_info(data)

        else:
            if self.output == "elf":
                with open(self.filepath, 'w+') as f:
                    print_status("Building ELF payload")
                    content = self.generate_elf(data)

                    print_success("Saving file {}".format(self.filepath))
                    f.write(content)

            elif self.output == "c":
                print_success("Bulding payload for C")
                content = self.generate_c(data)
                print_info(content)

            elif self.output == "python":
                print_success("Building payload for python")
                content = self.generate_python(data)
                print_info(content)

    def generate_elf(self, data):
        elf = self.header + data

        if self.bigendian:
            p_filesz = pack(">L", len(elf))
            p_memsz = pack(">L", len(elf) + len(data))
        else:
            p_filesz = pack("<L", len(elf))
            p_memsz = pack("<L", len(elf) + len(data))

        content = elf[:0x44] + p_filesz + p_memsz + elf[0x4c:]
        return content

    def generate_c(self, data):
        res = "unsigned char sh[] = {\n    \""
        for idx, x in enumerate(data):
            if idx % 15 == 0 and idx != 0:
                res += "\"\n    \""
            res += "\\x%02x" % ord(x)
        res += "\"\n};"
        return res

    def generate_python(self, data):
        res = "payload = (\n    \""
        for idx, x in enumerate(data):
            if idx % 15 == 0 and idx != 0:
                res += "\"\n    \""
            res += "\\x%02x" % ord(x)
        res += "\"\n)"
        return res
