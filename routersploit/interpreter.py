from __future__ import print_function
import os
import sys
import traceback
import atexit
import importlib
import inspect

from routersploit.exceptions import RoutersploitException
from routersploit.exploits import Exploit
from routersploit import utils
from routersploit import modules as rsf_modules

if sys.platform == "darwin":
    import gnureadline as readline
else:
    import readline


class BaseInterpreter(object):
    history_file = os.path.expanduser("~/.history")
    history_length = 100

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        """ Initialization of third-party libraries

        Setting interpreter history.
        Setting appropriate completer function.

        :return:
        """
        if not os.path.exists(self.history_file):
            open(self.history_file, 'a+').close()

        readline.read_history_file(self.history_file)
        readline.set_history_length(self.history_length)
        atexit.register(readline.write_history_file, self.history_file)

        readline.parse_and_bind('set enable-keypad on')

        readline.set_completer(self.complete)
        readline.set_completer_delims(' \t\n;')
        readline.parse_and_bind("tab: complete")

    def parse_line(self, line):
        """ Split line into command and argument.

        :param line: line to parse
        :return: (command, argument)
        """
        command, _, arg = line.strip().partition(" ")
        return command, arg.strip()

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.

        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            raise RoutersploitException("Unknown command: '{}'".format(command))

        return command_handler

    def start(self):
        """ Routersploit main entry point. Starting interpreter loop. """

        print(self.banner)
        while True:
            try:
                command, args = self.parse_line(raw_input(self.prompt))
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args)
            except RoutersploitException as err:
                utils.print_error(err)
            except (KeyboardInterrupt, EOFError):
                print()
                utils.print_status("routersploit stopped")
                break

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args = self.parse_line(line)
                if cmd == '':
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, 'complete_' + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer

            self.completion_matches = complete_function(text, line, start_index, end_index)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.

        :param ignored:
        :return: full list of interpreter commands
        """
        return [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return filter(lambda entry: entry.startswith(text), self.suggested_commands())

    def default_completer(self, *ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Overwrite this method to suggest suitable commands.

        :return: list of suitable commands
        """
        return self.commands()


class RoutersploitInterpreter(BaseInterpreter):
    history_file = os.path.expanduser("~/.rsf_history")

    def __init__(self):
        super(RoutersploitInterpreter, self).__init__()

        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.prompt_hostname = 'rsf'
        self.modules_directory = rsf_modules.__path__[0]
        self.modules = []
        self.modules_with_errors = {}
        self.main_modules_dirs = []

        self.__parse_prompt()
        self.load_modules()

        self.banner = """ ______            _            _____       _       _ _
 | ___ \          | |          /  ___|     | |     (_) |
 | |_/ /___  _   _| |_ ___ _ __\ `--. _ __ | | ___  _| |_
 |    // _ \| | | | __/ _ \ '__|`--. \ '_ \| |/ _ \| | __|
 | |\ \ (_) | |_| | ||  __/ |  /\__/ / |_) | | (_) | | |_
 \_| \_\___/ \__,_|\__\___|_|  \____/| .__/|_|\___/|_|\__|
                                     | |
     Router Exploitation Framework   |_|

 Dev Team : Marcin Bury (lucyoa) & Mariusz Kupidura (fwkz)
 Codename : Bad Blood
 Version  : 2.0.0

 Total module count: {modules_count}
""".format(modules_count=len(self.modules))

    def load_modules(self):
        self.main_modules_dirs = [module for module in os.listdir(self.modules_directory) if not module.startswith("__")]
        self.modules = []
        self.modules_with_errors = {}

        for root, dirs, files in os.walk(self.modules_directory):
            _, package, root = root.rpartition('routersploit')
            root = "".join((package, root)).replace(os.sep, '.')
            modules = map(lambda x: '.'.join((root, os.path.splitext(x)[0])), filter(lambda x: x.endswith('.py'), files))
            for module_path in modules:
                try:
                    module = importlib.import_module(module_path)
                except ImportError as error:
                    self.modules_with_errors[module_path] = error
                else:
                    klasses = inspect.getmembers(module, inspect.isclass)
                    exploits = filter(lambda x: issubclass(x[1], Exploit), klasses)
                    # exploits = map(lambda x: '.'.join([module_path.split('.', 2).pop(), x[0]]), exploits)
                    # self.modules.extend(exploits)
                    if exploits:
                        self.modules.append(module_path.split('.', 2).pop())

    def __parse_prompt(self):
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        raw_prompt_template = os.getenv("RSF_RAW_PROMPT", raw_prompt_default_template).replace('\\033', '\033')
        self.raw_prompt_template = raw_prompt_template if '{host}' in raw_prompt_template else raw_prompt_default_template

        module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[91m\002{module}\001\033[0m\002) > "
        module_prompt_template = os.getenv("RSF_MODULE_PROMPT", module_prompt_default_template).replace('\\033', '\033')
        self.module_prompt_template = module_prompt_template if all(map(lambda x: x in module_prompt_template, ['{host}', "{module}"])) else module_prompt_default_template

    @property
    def module_metadata(self):
        return getattr(self.current_module, "_{}__info__".format(self.current_module.__class__.__name__))

    @property
    def prompt(self):
        """ Returns prompt string based on current_module attribute.

        Adding module prefix (module.name) if current_module attribute is set.

        :return: prompt string with appropriate module prefix.
        """
        if self.current_module:
            try:
                return self.module_prompt_template.format(host=self.prompt_hostname, module=self.module_metadata['name'])
            except (AttributeError, KeyError):
                return self.module_prompt_template.format(host=self.prompt_hostname, module="UnnamedModule")
        else:
            return self.raw_prompt_template.format(host=self.prompt_hostname)

    def available_modules_completion(self, text):
        """ Looking for tab completion hints using setup.py entry_points.

        May need optimization in the future!

        :param text: argument of 'use' command
        :return: list of tab completion hints
        """
        text = utils.pythonize_path(text)
        all_possible_matches = filter(lambda x: x.startswith(text), self.modules)
        matches = set()
        for match in all_possible_matches:
            head, sep, tail = match[len(text):].partition('.')
            if not tail:
                sep = ""
            matches.add("".join((text, head, sep)))
        return list(map(utils.humanize_path, matches))  # humanize output, replace dots to forward slashes

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Based on state of interpreter this method will return intelligent suggestions.

        :return: list of most accurate command suggestions
        """
        if self.current_module:
            return ['run', 'back', 'set ', 'show ', 'check', 'debug', 'exit']
        else:
            return ['use ', 'debug', 'exit']

    def command_back(self, *args, **kwargs):
        self.current_module = None

    def command_use(self, module_path, *args, **kwargs):
        module_path = utils.pythonize_path(module_path)
        module_path = '.'.join(('routersploit', 'modules', module_path))
        # module_path, _, exploit_name = module_path.rpartition('.')
        try:
            module = importlib.import_module(module_path)
            self.current_module = getattr(module, 'Exploit')()
        except (ImportError, AttributeError, KeyError):
            utils.print_error("Error during loading '{}' module. "
                              "It should be valid path to the module. "
                              "Use <tab> key multiple times for completion.".format(utils.humanize_path(module_path)))

    @utils.stop_after(2)
    def complete_use(self, text, *args, **kwargs):
        if text:
            return self.available_modules_completion(text)
        else:
            return self.main_modules_dirs

    @utils.module_required
    def command_run(self, *args, **kwargs):
        utils.print_status("Running module...")
        try:
            self.current_module.run()
        except:
            utils.print_error(traceback.format_exc(sys.exc_info()))

    def command_exploit(self, *args, **kwargs):
        self.command_run()

    @utils.module_required
    def command_set(self, *args, **kwargs):
        key, _, value = args[0].partition(' ')
        if key in self.current_module.options:
            setattr(self.current_module, key, value)
            utils.print_success({key: value})
        else:
            utils.print_error("You can't set option '{}'.\n"
                              "Available options: {}".format(key, self.current_module.options))

    @utils.stop_after(2)
    def complete_set(self, text, *args, **kwargs):
        if text:
            return [' '.join((attr, "")) for attr in self.current_module.options if attr.startswith(text)]
        else:
            return self.current_module.options

    @utils.module_required
    def get_opts(self, *args):
        """ Generator returning module's Option attributes (option_name, option_value, option_description)

        :param args: Option names
        :return:
        """
        for opt_key in args:
            try:
                opt_description = self.current_module.exploit_attributes[opt_key]
                opt_value = getattr(self.current_module, opt_key)
            except (KeyError, AttributeError):
                pass
            else:
                yield opt_key, opt_value, opt_description

    @utils.module_required
    def command_show(self, *args, **kwargs):
        info, options = 'info', 'options'
        sub_command = args[0]
        if sub_command == info:
            utils.pprint_dict_in_order(
                self.module_metadata,
                ("name", "description", "targets", "authors", "references"),
            )
            utils.print_info()
        elif sub_command == options:
            target_opts = {'port', 'target'}
            module_opts = set(self.current_module.options) - target_opts
            headers = ("Name", "Current settings", "Description")

            utils.print_info('\nTarget options:')
            utils.print_table(headers, *self.get_opts(*target_opts))

            if module_opts:
                utils.print_info('\nModule options:')
                utils.print_table(headers, *self.get_opts(*module_opts))

            utils.print_info()
        else:
            print("Unknown command 'show {}'. You want to 'show {}' or 'show {}'?".format(sub_command, info, options))

    @utils.stop_after(2)
    def complete_show(self, text, *args, **kwargs):
        sub_commands = ['info', 'options']
        if text:
            return filter(lambda command: command.startswith(text), sub_commands)
        else:
            return sub_commands

    @utils.module_required
    def command_check(self, *args, **kwargs):
        try:
            result = self.current_module.check()
        except:
            utils.print_error(traceback.format_exc(sys.exc_info()))
        else:
            if result is True:
                utils.print_success("Target is vulnerable")
            elif result is False:
                utils.print_error("Target is not vulnerable")
            else:
                utils.print_status("Target could not be verified")

    def command_debug(self, *args, **kwargs):
        for key, value in self.modules_with_errors.iteritems():
            utils.print_info(key)
            utils.print_error(value, '\n')

    def command_exit(self, *args, **kwargs):
        raise KeyboardInterrupt
