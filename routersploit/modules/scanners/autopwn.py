import threading
from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_info,
    utils,
    LockedIterator,
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

    target = exploits.Option('', 'Target IP address e.g. 192.168.1.1')  # target address
    port = exploits.Option(80, 'Target port')  # default port
    threads = exploits.Option(8, "Number of threads")

    def run(self):
        data = LockedIterator(utils.iter_modules(utils.EXPLOITS_DIR))
        self.vulnerabilities = []
        self.run_threads(self.threads, self.target_function, data)

        if self.vulnerabilities:
            print_info()
            print_success("Device is vulnerable!")
            for v in self.vulnerabilities:
                print_info(" - {}".format(v))
        else:
            print_error("Device is not vulnerable to any exploits!\n")

    def check(self):
        raise NotImplementedError("Check method is not available")

    def target_function(self, running, data):
        name = threading.current_thread().name
        print_status(name, 'process is starting...')

        while running.is_set():
            try:
                exploit = data.next()
            except StopIteration:
                break
            else:
                exploit = exploit()
                exploit.target = self.target
                exploit.port = self.port

                response = exploit.check()

                if response is True:
                    print_success("{} {} is vulnerable".format(name, exploit))
                    self.vulnerabilities.append(exploit)
                elif response is False:
                    print_error("{} {} is not vulnerable".format(name, exploit))
                else:
                    print_status("{} {} could not be verified".format(name, exploit))
