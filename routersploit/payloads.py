from struct import pack

from routersploit import exploits
from routersploit.exceptions import RoutersploitException
from utils import (
    print_success,
    print_status,
    print_info,
    random_text
)

ARCH_ELF_HEADERS = {
    "armle": (
        "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
        "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00"
        "\x00\x80\x00\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
        "\x00\x10\x00\x00"
    ),
    "mipsbe": (
        "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\x54\x00\x00\x00\x34"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00"
        "\x00\x40\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xef\x00\x00\x00\x07"
        "\x00\x00\x10\x00"
    ),
    "mipsle": (
        "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x02\x00\x08\x00\x01\x00\x00\x00\x54\x00\x40\x00\x34\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
        "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00"
        "\x00\x00\x40\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
        "\x00\x10\x00\x00"
    )
}


class Payload(exploits.BaseExploit):

    architecture = None

    output = exploits.Option('python', 'Output type: elf/python')
    filepath = exploits.Option(
        "/tmp/{}".format(random_text(8)), 'Output file to write'
    )

    def __init__(self):
        if self.architecture is None:
            raise RoutersploitException("Please set appropriate architecture")

        self.header = ARCH_ELF_HEADERS[self.architecture]
        self.bigendian = True if self.architecture.endswith("be") else False

    def generate(self):
        raise NotImplementedError("Please implement payload generation.")

    def check(self):
        raise NotImplementedError("Check method is not available")

    def run(self):
        print_status("Generating payload")
        payload = self.generate()

        if self.output == "elf":
            with open(self.filepath, 'w+') as f:
                print_status("Building ELF payload")
                content = self.generate_elf(payload)

                print_success("Saving file {}".format(self.filepath))
                f.write(content)

        elif self.output == "python":
            print_success("Building payload for python")
            content = self.generate_python(payload)
            print_info(content)

    def generate_elf(self, payload):
        elf = self.header + payload

        if self.bigendian:
            p_filesz = pack(">L", len(elf))
            p_memsz = pack(">L", len(elf) + len(payload))
        else:
            p_filesz = pack("<L", len(elf))
            p_memsz = pack("<L", len(elf) + len(payload))

        content = elf[:0x44] + p_filesz + p_memsz + elf[0x4c:]
        return content

    def generate_python(self, payload):
        res = "payload = (\n    \""
        for idx, x in enumerate(payload):
            if idx % 15 == 0 and idx != 0:
                res += "\"\n    \""

            res += "\\x%02x" % ord(x)
        res += "\"\n)"
        return res
