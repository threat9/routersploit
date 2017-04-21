from os import path

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_info,
    utils,
    threads,
)


class Exploit(exploits.Exploit):
    """
    Scanner implementation for all vulnerabilities.
    """
    __info__ = {
        'name': 'AutoPwn',
        'description': 'Scanner module for all vulnerabilities.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Multi',
        ),
    }
    modules = ['routers', 'cameras', 'misc']

    target = exploits.Option('', 'Target IP address e.g. 192.168.1.1')  # target address
    port = exploits.Option(80, 'Target port')  # default port
    threads = exploits.Option(8, "Number of threads")

    def __init__(self):
        self.vulnerabilities = []
        self.not_verified = []
        self._exploits_directories = [path.join(utils.EXPLOITS_DIR, module) for module in self.modules]

    def run(self):
        self.vulnerabilities = []
        self.not_verified = []

        with threads.ThreadPoolExecutor(self.threads) as executor:
            for directory in self._exploits_directories:
                for exploit in utils.iter_modules(directory):
                    executor.submit(self.target_function, exploit)

        print_info()
        if self.not_verified:
            print_status("Could not verify exploitability:")
            for v in self.not_verified:
                print_info(" - {}".format(v))

        print_info()
        if self.vulnerabilities:
            print_success("Device is vulnerable:")
            for v in self.vulnerabilities:
                print_info(" - {}".format(v))
            print_info()
        else:
            print_error("Could not confirm any vulnerablity\n")

    def check(self):
        raise NotImplementedError("Check method is not available")

    def target_function(self, exploit):
        exploit = exploit()
        exploit.target = self.target
        exploit.port = self.port

        response = exploit.check()

        if response is True:
            print_success("{} is vulnerable".format(exploit))
            self.vulnerabilities.append(exploit)
        elif response is False:
            print_error("{} is not vulnerable".format(exploit))
        else:
            print_status("{} could not be verified".format(exploit))
            self.not_verified.append(exploit)
