from routersploit.modules.scanners.autopwn import Exploit


class Exploit(Exploit):
    __info__ = {
        "name": "Router Scanner",
        "description": "Module that scans for routers vulnerablities and weaknesses.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Router",
        ),
    }

    modules = ["generic", "routers"]
