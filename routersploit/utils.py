from __future__ import print_function
from __future__ import absolute_import
import threading
import os
import sys
import random
import string
import socket
from functools import wraps
from distutils.util import strtobool
import importlib

import requests

from .exceptions import RoutersploitException
from . import modules as rsf_modules


MODULES_DIR = rsf_modules.__path__[0]

print_lock = threading.Lock()

colors = {
    'grey': 30,  'red': 31,
    'green': 32, 'yellow': 33,
    'blue': 34,  'magenta': 35,
    'cyan': 36,  'white': 37,
}


def index_modules(modules_directory=MODULES_DIR):
    """ Return list of all exploits modules """

    modules = []
    for root, dirs, files in os.walk(modules_directory):
        _, package, root = root.rpartition('routersploit/modules/'.replace('/', os.sep))
        root = root.replace(os.sep, '.')
        files = filter(lambda x: not x.startswith("__") and x.endswith('.py'), files)
        modules.extend(map(lambda x: '.'.join((root, os.path.splitext(x)[0])), files))

    return modules


def import_exploit(path):
    """ Import exploit module

    :param path: absolute path to exploit e.g. routersploit.modules.exploits.asus.pass_bypass
    :return: exploit module or error
    """
    try:
        module = importlib.import_module(path)
        return getattr(module, 'Exploit')
    except (ImportError, AttributeError, KeyError) as err:
        raise RoutersploitException(
            "Error during loading '{}'\n\n"
            "Error: {}\n\n"
            "It should be valid path to the module. "
            "Use <tab> key multiple times for completion.".format(humanize_path(path), err)
        )


def iter_modules(modules_directory=MODULES_DIR):
    """ Iterate over valid modules """

    modules = index_modules(modules_directory)
    modules = map(lambda x: "".join(['routersploit.modules.', x]), modules)
    for path in modules:
        try:
            yield import_exploit(path)
        except RoutersploitException:
            pass


def pythonize_path(path):
    """ Replace argument to valid python dotted notation.

    ex. foo/bar/baz -> foo.bar.baz
    """
    return path.replace('/', '.')


def humanize_path(path):
    """ Replace python dotted path to directory-like one.

    ex. foo.bar.baz -> foo/bar/baz

    :param path: path to humanize
    :return: humanized path

    """
    return path.replace('.', '/')


def module_required(fn):
    """ Checks if module is loaded.

    Decorator that checks if any module is activated
    before executing command specific to modules (ex. 'run').
    """
    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        if not self.current_module:
            print_error("You have to activate any module with 'use' command.")
            return
        return fn(self, *args, **kwargs)
    try:
        name = 'module_required'
        wrapper.__decorators__.append(name)
    except AttributeError:
        wrapper.__decorators__ = [name]
    return wrapper


def stop_after(space_number):
    """ Decorator that determine when to stop tab-completion

    Decorator that tells command specific complete function
    (ex. "complete_use") when to stop tab-completion.
    Decorator counts number of spaces (' ') in line in order
    to determine when to stop.

        ex. "use exploits/dlink/specific_module " -> stop complete after 2 spaces
        "set rhost " -> stop completing after 2 spaces
        "run " -> stop after 1 space

    :param space_number: number of spaces (' ') after which tab-completion should stop
    :return:
    """
    def _outer_wrapper(wrapped_function):
        @wraps(wrapped_function)
        def _wrapper(self, *args, **kwargs):
            try:
                if len(args[1].split(' ', space_number)) == space_number + 1:
                    return []
            except Exception as err:
                print(err)
            return wrapped_function(self, *args, **kwargs)
        return _wrapper
    return _outer_wrapper


class DummyFile(object):
    """  Mocking file object. Optimalization for the "mute" decorator. """
    def write(self, x): pass


def mute(fn):
    """ Suppress function from printing to sys.stdout """
    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        sys.stdout = DummyFile()
        try:
            return fn(self, *args, **kwargs)
        finally:
            sys.stdout = sys.__stdout__
    return wrapper


def multi(fn):
    """ Decorator for exploit.Exploit class

    Decorator that allows to feed exploit using text file containing
    multiple targets definition. Decorated function will be executed
    as many times as there is targets in the feed file.

    WARNING:
    Important thing to remember is fact that decorator will
    suppress values returned by decorated function. Since method that
    perform attack is not suppose to return anything this is not a problem.

    """
    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        if self.target.startswith('file://'):
            original_target = self.target
            original_port = self.port

            _, _, feed_path = self.target.partition("file://")
            try:
                with open(feed_path) as file_handler:
                    for target in file_handler:
                        target = target.strip()
                        if not target:
                            continue
                        self.target, _, port = target.partition(':')
                        if port:
                            self.port = port
                        else:
                            self.port = original_port
                        print_status("Attack against: {}:{}".format(self.target,
                                                                    self.port))
                        fn(self, *args, **kwargs)
                    self.target = original_target
                    self.port = original_port
                    return  # Nothing to return, ran multiple times.
            except IOError:
                print_error("Could not read file: {}".format(self.target))
                return

        else:
            return fn(self, *args, **kwargs)
    return wrapper


def __cprint(*args, **kwargs):
    """ Color print()

    Signature like Python 3 print() function
    print([object, ...][, sep=' '][, end='\n'][, file=sys.stdout])
    """
    if not kwargs.pop("verbose", True):
        return

    with print_lock:
        color = kwargs.get('color', None)
        if color:
            file_ = kwargs.get('file', sys.stdout)
            sep = kwargs.get('sep', ' ')
            end = kwargs.get('end', '\n')
            print('\033[{}m'.format(colors[color]), end='', file=file_, sep=sep)
            print(*args, end='', file=file_, sep=sep)  # TODO printing text that starts from newline
            print('\033[0m', sep=sep, end=end, file=file_)
        else:
            print(*args, **kwargs)


def print_error(*args, **kwargs):
    __cprint('\033[91m[-]\033[0m', *args, **kwargs)


def print_status(*args, **kwargs):
    __cprint('\033[94m[*]\033[0m', *args, **kwargs)


def print_success(*args, **kwargs):
    __cprint('\033[92m[+]\033[0m', *args, **kwargs)


def print_info(*args, **kwargs):
    __cprint(*args, **kwargs)


class LockedIterator(object):
    def __init__(self, it):
        self.lock = threading.Lock()
        self.it = it.__iter__()

    def __iter__(self):
        return self

    def next(self):
        self.lock.acquire()
        try:
            return self.it.next()
        finally:
            self.lock.release()


def print_table(headers, *args, **kwargs):
    """ Print table.

    example:

    Name            Current setting     Description
    ----            ---------------     -----------
    option_name     value               description
    foo             bar                 baz
    foo             bar                 baz

    :param headers: Headers names ex.('Name, 'Current setting', 'Description')
    :param args: table values, each element representing one line ex. ('option_name', 'value', 'description), ...
    :param kwargs: 'extra_fill' space between columns, 'header_separator' character to separate headers from content
    :return:
    """
    extra_fill = kwargs.get("extra_fill", 5)
    header_separator = kwargs.get("header_separator", '-')

    if not all(map(lambda x: len(x) == len(headers), args)):
        print_error("Headers and table rows tuples should be the same length.")
        return

    def custom_len(x):
        try:
            return len(x)
        except TypeError:
            return 0

    fill = []
    headers_line = '   '
    headers_separator_line = '   '
    for idx, header in enumerate(headers):
        current_line_fill = max(len(header), *map(lambda x: custom_len(x[idx]), args)) + extra_fill
        fill.append(current_line_fill)
        headers_line = "".join((headers_line, "{header:<{fill}}".format(header=header, fill=current_line_fill)))
        headers_separator_line = "".join((
            headers_separator_line,
            '{:<{}}'.format(header_separator * len(header), current_line_fill)
        ))

    print()
    print(headers_line)
    print(headers_separator_line)
    for arg in args:
        content_line = '   '
        for idx, element in enumerate(arg):
            content_line = "".join((
                content_line,
                '{:<{}}'.format(element, fill[idx])
            ))
        print(content_line)

    print()


def sanitize_url(address):
    """Sanitize url.

    Converts address to valid HTTP url.
    """
    if address.startswith("http://") or address.startswith("https://"):
        return address
    else:
        return "http://{}".format(address)


def pprint_dict_in_order(dictionary, order=None):
    """ Pretty dict print.

    Pretty printing dictionary in specific order. (as in 'show info' command)
    Keys not mentioned in *order* parameter will be printed in random order.

    ex. pprint_dict_in_order({'name': John, 'sex': 'male', "hobby": ["rugby", "golf"]}, ('sex', 'name'))

    Sex:
    male

    Name:
    John

    Hobby:
    - rugby
    - golf

    """
    order = order or ()

    def prettyprint(title, body):
        print_info("\n{}:".format(title.capitalize()))
        if not isinstance(body, str):
            for value_element in value:
                print_info('- ', value_element)
        else:
            print_info(value)

    keys = dictionary.keys()
    for element in order:
        try:
            key = keys.pop(keys.index(element))
            value = dictionary[key]
        except (KeyError, ValueError):
            pass
        else:
            prettyprint(element, value)

    for rest_keys in keys:
        prettyprint(rest_keys, dictionary[rest_keys])


def random_text(length, alph=string.ascii_letters+string.digits):
    """ Random text generator. NOT crypto safe.
    
    Generates random text with specified length and alphabet.
    """
    return ''.join(random.choice(alph) for _ in range(length))


def http_request(method, url, **kwargs):
    """ Wrapper for 'requests' silencing exceptions a little bit. """

    kwargs.setdefault('timeout', 30.0)
    kwargs.setdefault('verify', False)

    try:
        return getattr(requests, method.lower())(url, **kwargs)
    except (requests.exceptions.MissingSchema, requests.exceptions.InvalidSchema):
        print_error("Invalid URL format: {}".format(url))
        return
    except requests.exceptions.ConnectionError:
        print_error("Connection error: {}".format(url))
        return
    except requests.RequestException as error:
        print_error(error)
        return
    except socket.error as err:
        print_error(err)
        return
    except KeyboardInterrupt:
        print_info()
        print_status("Module has been stopped")


def boolify(value):
    """ Function that will translate common strings into bool values

    True -> "True", "t", "yes", "y", "on", "1"
    False -> any other string

    Objects other than string will be transformed using built-in bool() function.
    """
    if isinstance(value, basestring):
        try:
            return bool(strtobool(value))
        except ValueError:
            return False
    else:
        return bool(value)
