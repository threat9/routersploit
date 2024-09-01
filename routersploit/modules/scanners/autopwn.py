import os
import sys

from routersploit.core.exploit import *
from routersploit.core.exploit.exploit import Protocol


class Exploit(Exploit):
    __info__ = {
        "name": "AutoPwn",
        "description": "Module scans for all vulnerabilities and weaknesses.",
        "authors": (
            "Marcin Bury <marcin[at]threat9.com>",  # routersploit module
        ),
        "devices": (
            "Multi",
        ),
    }

    modules = ["generic", "routers", "cameras", "misc"]

    target = OptIP("", "Target IPv4 or IPv6 address")

    vendor = OptString("any", "Vendor concerned (default: any)")

    check_exploits = OptBool(True, "Check exploits against target: true/false", advanced=True)
    check_creds = OptBool(True, "Check factory credentials against target: true/false", advanced=True)

    http_use = OptBool(True, "Check HTTP[s] service: true/false")
    http_port = OptPort(80, "Target Web Interface Port", advanced=True)
    http_ssl = OptBool(False, "HTTPS enabled: true/false")

    ftp_use = OptBool(True, "Check FTP[s] service: true/false")
    ftp_port = OptPort(21, "Target FTP port (default: 21)", advanced=True)
    ftp_ssl = OptBool(False, "FTPS enabled: true/false")

    ssh_use = OptBool(True, "Check SSH service: true/false")
    ssh_port = OptPort(22, "Target SSH port (default: 22)", advanced=True)

    telnet_use = OptBool(True, "Check Telnet service: true/false")
    telnet_port = OptPort(23, "Target Telnet port (default: 23)", advanced=True)

    snmp_use = OptBool(True, "Check SNMP service: true/false")
    snmp_community = OptString("public", "Target SNMP community name (default: public)", advanced=True)
    snmp_port = OptPort(161, "Target SNMP port (default: 161)", advanced=True)

    tcp_use = OptBool(True, "Check custom TCP services", advanced=True)
    udp_use = OptBool(True, "Check custom UDP services", advanced=True)

    threads = OptInteger(8, "Number of threads")

    def __init__(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []
        self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module) for module in self.modules]
        self._creds_directories = [os.path.join(utils.MODULES_DIR, "creds", module) for module in self.modules]

    def run(self):
        ip_list_file = input("Please enter the path to the IP list text file: ").strip()
        if os.path.exists(ip_list_file):
            with open(ip_list_file, 'r') as f:
                ips = [line.strip() for line in f.readlines()]
            for ip in ips:
                self.target = ip
                self.scan_target()
        else:
            print(f"File '{ip_list_file}' not found. Please check the path and try again.")

    def scan_target(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []

        # Update list of directories with specific vendor if needed
        if self.vendor != 'any':
            self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module, self.vendor) for module in self.modules]

        if self.check_exploits:
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting vulnerability check...".format(self.target))

            modules = []
            for directory in self._exploits_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

            data = LockedIterator(modules)
            self.run_threads(self.threads, self.exploits_target_function, data)

        if self.check_creds:
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting default credentials check...".format(self.target))

            modules = []
            for directory in self._creds_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

            data = LockedIterator(modules)
            self.run_threads(self.threads, self.creds_target_function, data)

        self.print_results()

    def print_results(self):
        print_info()
        if self.not_verified:
            print_info("\033[94m[*]\033[0m", "{} Could not verify exploitability:".format(self.target))
            for v in self.not_verified:
                print_info(" - {}:{} {} {}".format(*v))
            print_info()

        if self.vulnerabilities:
            print_info("\033[92m[+]\033[0m", "{} Device is vulnerable:".format(self.target))
            headers = ("Target", "Port", "Service", "Exploit")
            print_table(headers, *self.vulnerabilities)
            print_info()
        else:
            print_info("\033[91m[-]\033[0m", "{} Could not confirm any vulnerability\n".format(self.target))

        if self.creds:
            print_info("\033[92m[+]\033[0m", "{} Found default credentials:".format(self.target))
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.creds)
            print_info()
        else:
            print_info("\033[91m[-]\033[0m", "{} Could not find default credentials".format(self.target))

    # The existing functions (exploits_target_function, creds_target_function) remain unchanged
