from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_info,
    utils,
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

    def run(self):
        vulnerabilities = []

        for exploit in utils.iter_modules(utils.EXPLOITS_DIR):
            exploit = exploit()
            exploit.target = self.target
            exploit.port = self.port

            response = exploit.check()

            if response is True:
                print_success("{} is vulnerable".format(exploit))
                vulnerabilities.append(exploit)
            elif response is False:
                print_error("{} is not vulnerable".format(exploit))
            else:
                print_status("{} could not be verified".format(exploit))

        if vulnerabilities:
            print_info()
            print_success("Device is vulnerable!")
            for v in vulnerabilities:
                print_info(" - {}".format(v))
        else:
            print_error("Device is not vulnerable to any exploits!\n")

    def check(self):
        raise NotImplementedError("Check method is not available")
