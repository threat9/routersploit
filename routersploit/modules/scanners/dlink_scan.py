from os import listdir
from os.path import isfile, join
import imp

from routersploit import (
    exploits,
    print_success,
    print_error,
    print_status,
)


class Exploit(exploits.Exploit):
    """
    D-Link Scanner
    """
    __info__ = {
        'name': 'D-Link Scanner',
        'description': 'Scanner module for D-Link devices',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': (
            '',
        ),
        'devices': (
            'Multi',
        )
    }

    target = exploits.Option('', 'Target IP address e.g. 192.168.1.1')  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        rootpath = 'routersploit/modules/'
        path = 'exploits/dlink/'

        # only py exploit files
        modules = [f.replace(".py", "") for f in listdir(rootpath + path) if isfile(join(rootpath + path, f)) and f.endswith(".py") and f != "__init__.py"]

        vulns = []
        for module_name in modules:
            f = path + module_name

            module = imp.load_source('module', rootpath + f + '.py')
            exploit = module.Exploit()

            exploit.target = self.target
            exploit.port = self.port

            res = exploit.check()

            if res is True:
                print_success("{} is vulnerable".format(f))
                vulns.append(f)
            elif res is False:
                print_error("{} is not vulnerable".format(f))
            else:
                print_status("{} could not be verified".format(f))

        print
        if len(vulns):
            print_success("Device is vulnerable!")
            for v in vulns:
                print " - {}".format(v)
        else:
            print_error("Device is not vulnerable to any exploits!")
        print

    def check(self):
        raise NotImplementedError("Check method is not available")
