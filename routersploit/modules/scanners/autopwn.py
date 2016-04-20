from os import listdir
import imp

from routersploit import (
    exploits,
    print_error,
    print_success,
    print_status,
    print_info,
)


class Exploit(exploits.Exploit):
    """
    Scanner implementation for all vulnerabilities.
    """
    __info__ = {
        'name': 'AutoPwn',
        'description': 'Scanner module for all vulnerabilities.',
        'author': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
         ],
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1')  # target address
    port = exploits.Option(80, 'Target port')  # default port

    def run(self):
        rootpath = 'routersploit/modules/'
        path = 'exploits'

        modules = []
        for device in listdir(rootpath+path):  # TODO refactor this, using load_modules() from core
            if not device.endswith(".py") and not device.endswith(".pyc"):
                for f in listdir(rootpath+path + "/" + device):
                    if f.endswith(".py") and f != "__init__.py":
                        modules.append(device + "/" + f[:-3])

        vulnerabilities = []
        for module_name in modules:
            f = "".join((path, "/", module_name))

            module = imp.load_source('module', rootpath + f + '.py')
            exploit = module.Exploit()

            exploit.target = self.target
            exploit.port = self.port

            response = exploit.check()

            if response is True:
                print_success("{} is vulnerable".format(f))
                vulnerabilities.append(f)
            elif response is False:
                print_error("{} is not vulnerable".format(f))
            else:
                print_status("{} could not be verified".format(f))

        if vulnerabilities:
            print
            print_success("Device is vulnerable!")
            for v in vulnerabilities:
                print_info(" - {}".format(v))
        else:
            print_error("Device is not vulnerable to any exploits!\n")
        
    def check(self):
        print_error("Check method is not available")
