from collections import namedtuple
from struct import pack

from routersploit import exploits, validators
from routersploit.exceptions import OptionValidationError
from utils import print_info, print_status, print_success, print_error, random_text


architectures = namedtuple("ArchitectureType", ["ARMLE", "MIPSBE", "MIPSLE"])
payload_handlers = namedtuple("PayloadHandlers", ["BIND_TCP", "REVERSE_TCP"])

Architectures = architectures(
    ARMLE="armle",
    MIPSBE="mipsbe",
    MIPSLE="mipsle",
)

PayloadHandlers = payload_handlers(
    BIND_TCP="bind_tcp",
    REVERSE_TCP="reverse_tcp",
)

ARCH_ELF_HEADERS = {
    Architectures.ARMLE: (
        "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x02\x00\x28\x00\x01\x00\x00\x00\x54\x80\x00\x00\x34\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
        "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00"
        "\x00\x80\x00\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
        "\x00\x10\x00\x00"
    ),
    Architectures.MIPSBE: (
        "\x7f\x45\x4c\x46\x01\x02\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x02\x00\x08\x00\x00\x00\x01\x00\x40\x00\x54\x00\x00\x00\x34"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x40\x00\x00"
        "\x00\x40\x00\x00\xde\xad\xbe\xef\xde\xad\xbe\xef\x00\x00\x00\x07"
        "\x00\x00\x10\x00"
    ),
    Architectures.MIPSLE: (
        "\x7f\x45\x4c\x46\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x02\x00\x08\x00\x01\x00\x00\x00\x54\x00\x40\x00\x34\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x34\x00\x20\x00\x01\x00\x00\x00"
        "\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00"
        "\x00\x00\x40\x00\xef\xbe\xad\xde\xef\xbe\xad\xde\x07\x00\x00\x00"
        "\x00\x10\x00\x00"
    ),
}


class ReverseTCPPayloadMixin(object):
    __metaclass__ = exploits.ExploitOptionsAggregator

    handler = PayloadHandlers.REVERSE_TCP
    lhost = exploits.Option('', 'Connect-back IP address',
                            validators=validators.ipv4)
    lport = exploits.Option(5555, 'Connect-back TCP Port',
                            validators=validators.integer)


class BindTCPPayloadMixin(object):
    __metaclass__ = exploits.ExploitOptionsAggregator

    handler = PayloadHandlers.BIND_TCP
    rport = exploits.Option(5555, 'Bind Port',
                            validators=validators.integer)


class BasePayload(exploits.BaseExploit):
    handler = None

    def __init__(self):
        if self.handler not in PayloadHandlers:
            raise OptionValidationError(
                "Please use one of valid payload handlers: {}".format(
                    PayloadHandlers._fields
                )
            )

    def generate(self):
        raise NotImplementedError("Please implement 'generate()' method")

    def run(self):
        raise NotImplementedError()


class ArchitectureSpecificPayload(BasePayload):
    architecture = None

    output = exploits.Option('python', 'Output type: elf/c/python')
    filepath = exploits.Option(
        "/tmp/{}".format(random_text(8)), 'Output file to write'
    )

    def __init__(self):
        super(ArchitectureSpecificPayload, self).__init__()
        if self.architecture not in Architectures:
            raise OptionValidationError(
                "Please use one of valid payload architectures: {}".format(
                    Architectures._fields
                )
            )

        self.header = ARCH_ELF_HEADERS[self.architecture]
        self.bigendian = True if self.architecture.endswith("be") else False

    def run(self):
        print_status("Generating payload")
        try:
            data = self.generate()
        except OptionValidationError as e:
            print_error(e)
            return

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
        else:
            raise OptionValidationError(
                "No such option as {}".format(self.output)
            )

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

    @staticmethod
    def generate_c(data):
        res = "unsigned char sh[] = {\n    \""
        for idx, x in enumerate(data):
            if idx % 15 == 0 and idx != 0:
                res += "\"\n    \""
            res += "\\x%02x" % ord(x)
        res += "\"\n};"
        return res

    @staticmethod
    def generate_python(data):
        res = "payload = (\n    \""
        for idx, x in enumerate(data):
            if idx % 15 == 0 and idx != 0:
                res += "\"\n    \""
            res += "\\x%02x" % ord(x)
        res += "\"\n)"
        return res


class GenericPayload(BasePayload):
    def run(self):
        print_status("Generating payload")
        print_info(
            self.generate()
        )
