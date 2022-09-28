import os

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
    # tcp_port = OptPort(None, "Restrict TCP custom service tests to specific port (default: None)")

    udp_use = OptBool(True, "Check custom UDP services", advanced=True)
    # udp_port = OptPort(None, "Restrict UDP custom service tests to specific port (default: None)")

    threads = OptInteger(8, "Number of threads")

    def __init__(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []
        self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module) for module in self.modules]
        self._creds_directories = [os.path.join(utils.MODULES_DIR, "creds", module) for module in self.modules]

    def run(self):
        self.vulnerabilities = []
        self.creds = []
        self.not_verified = []

        # Update list of directories with specific vendor if needed
        if self.vendor != 'any':
            self._exploits_directories = [os.path.join(utils.MODULES_DIR, "exploits", module, self.vendor) for module in self.modules]

        if self.check_exploits:
            # vulnerabilities
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting vulnerablity check...".format(self.target))

            modules = []
            for directory in self._exploits_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

            data = LockedIterator(modules)
            self.run_threads(self.threads, self.exploits_target_function, data)

        if self.check_creds:
            # default creds
            print_info()
            print_info("\033[94m[*]\033[0m", "{} Starting default credentials check...".format(self.target))
            modules = []
            for directory in self._creds_directories:
                for module in utils.iter_modules(directory):
                    modules.append(module)

            data = LockedIterator(modules)
            self.run_threads(self.threads, self.creds_target_function, data)

        # results:
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
            print_info("\033[91m[-]\033[0m", "{} Could not confirm any vulnerablity\n".format(self.target))

        if self.creds:
            print_info("\033[92m[+]\033[0m", "{} Found default credentials:".format(self.target))
            headers = ("Target", "Port", "Service", "Username", "Password")
            print_table(headers, *self.creds)
            print_info()
        else:
            print_info("\033[91m[-]\033[0m", "{} Could not find default credentials".format(self.target))

    def exploits_target_function(self, running, data):
        while running.is_set():
            try:
                module = data.next()
                exploit = module()
            except StopIteration:
                break
            else:
                exploit.target = self.target

                # Avoid checking specific protocol - reduce network impact
                if exploit.target_protocol == Protocol.HTTP:
                    if not self.http_use:
                        continue
                    exploit.port = self.http_port
                    if self.http_ssl:
                        exploit.ssl = "true"
                        exploit.target_protocol = Protocol.HTTPS

                elif exploit.target_protocol is Protocol.FTP:
                    if not self.ftp_use:
                        continue
                    exploit.port = self.ftp_port
                    if self.ftp_ssl:
                        exploit.ssl = "true"
                        exploit.target_protocol = Protocol.FTPS

                elif exploit.target_protocol is Protocol.TELNET:
                    if not self.telnet_use:
                        continue
                    exploit.port = self.telnet_port

                elif exploit.target_protocol is Protocol.SSH:
                    if not self.ssh_use:
                        continue
                    exploit.port = self.ssh_port

                elif exploit.target_protocol is Protocol.SNMP:
                    if not self.snmp_use:
                        continue
                    exploit.port = self.ssh_port

                elif exploit.target_protocol is Protocol.TCP:
                    if not self.tcp_use:
                        continue

                elif exploit.target_protocol is Protocol.UDP:
                    if not self.udp_use:
                        continue

        #        elif exploit.target_protocol not in ["tcp", "udp"]:
        #            exploit.target_protocol = "custom"

                response = exploit.check()

                if response is True:
                    print_info("\033[92m[+]\033[0m", "{}:{} {} {} is vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                    self.vulnerabilities.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))
                elif response is False:
                    print_info("\033[91m[-]\033[0m", "{}:{} {} {} is not vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                else:
                    print_info("\033[94m[*]\033[0m", "{}:{} {} {} Could not be verified".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
                    self.not_verified.append((exploit.target, exploit.port, exploit.target_protocol, str(exploit)))

    def creds_target_function(self, running, data):
        while running.is_set():
            try:
                module = data.next()
                exploit = module()

                generic = False
                if exploit.__module__.startswith("routersploit.modules.creds.generic"):
                    if exploit.__module__.endswith("default"):
                        generic = True
                    else:
                        continue

            except StopIteration:
                break
            else:
                exploit.target = self.target
                exploit.verbosity = "false"
                exploit.stop_on_success = "false"
                exploit.threads = self.threads

                if exploit.target_protocol == Protocol.HTTP:
                    exploit.port = self.http_port
                    if self.http_ssl:
                        exploit.ssl = "true"
                        exploit.target_protocol = Protocol.HTTPS

                elif generic:
                    if exploit.target_protocol is Protocol.HTTP:
                        exploit.port = self.http_port
                        if self.http_ssl:
                            exploit.ssl = "true"
                            exploit.target_protocol = Protocol.HTTPS
                    elif exploit.target_protocol == Protocol.SSH:
                        exploit.port = self.ssh_port
                    elif exploit.target_protocol == Protocol.FTP:
                        exploit.port = self.ftp_port
                        if self.ftp_ssl:
                            exploit.ssl = "true"
                            exploit.target_protocol = Protocol.FTPS

                    elif exploit.target_protocol == Protocol.TELNET:
                        exploit.port = self.telnet_port
                else:
                    continue

                response = exploit.check_default()
                if response:
                    print_info("\033[92m[+]\033[0m", "{}:{} {} {} is vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))

                    for creds in response:
                        self.creds.append(creds)
                else:
                    print_info("\033[91m[-]\033[0m", "{}:{} {} {} is not vulnerable".format(
                               exploit.target, exploit.port, exploit.target_protocol, exploit))
