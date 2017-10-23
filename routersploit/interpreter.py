from __future__ import print_function

import atexit
import itertools
import os
import sys
import traceback
from collections import Counter

from routersploit import utils
from routersploit.exceptions import RoutersploitException
from routersploit.exploits import Exploit, GLOBAL_OPTS
from routersploit.payloads import BasePayload
from routersploit.printer import PrinterThread, printer_queue

if sys.platform == "darwin":
    import gnureadline as readline
else:
    import readline


class BaseInterpreter(object):
    history_file = os.path.expanduser("~/.history")
    history_length = 100
    global_help = ""

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

        utils.print_info(self.banner)
        printer_queue.join()
        while True:
            try:
                command, args = self.parse_line(raw_input(self.prompt))
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args)
            except RoutersploitException as err:
                utils.print_error(err)
            except EOFError:
                utils.print_info()
                utils.print_status("routersploit stopped")
                break
            except KeyboardInterrupt:
                utils.print_info()
            finally:
                printer_queue.join()

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
    global_help = """Global commands:
    help                        Print this help menu
    use <module>                Select a module for usage
    exec <shell command> <args> Execute a command in a shell
    search <search term>        Search for appropriate module
    exit                        Exit RouterSploit"""

    module_help = """Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    unsetg <option name>                Unset option that was set globally
    show [info|options|devices]         Print information, options, or target devices for a module
    check                               Check if a given target is vulnerable to a selected module's exploit"""

    def __init__(self):
        super(RoutersploitInterpreter, self).__init__()
        PrinterThread().start()

        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.prompt_hostname = 'rsf'
        self.show_sub_commands = (
            'info', 'options', 'devices', 'all',
            'creds', 'exploits', 'scanners'
        )

        self.global_commands = sorted(
            ['use ', 'exec ', 'help', 'exit', 'show ', 'search ']
        )
        self.module_commands = self._extend_with_global_commands(
            ['run', 'back', 'set ', 'setg ', 'check']
        )
        self.payload_commands = self._extend_with_global_commands(
            ['run', 'back', 'set ', 'setg ']
        )

        self.modules = utils.index_modules()
        self.modules_count = Counter()
        [self.modules_count.update(module.split('.')) for module in self.modules]
        self.main_modules_dirs = [module for module in os.listdir(utils.MODULES_DIR) if not module.startswith("__")]

        self.__parse_prompt()

        self.banner = """ ______            _            _____       _       _ _
 | ___ \          | |          /  ___|     | |     (_) |
 | |_/ /___  _   _| |_ ___ _ __\ `--. _ __ | | ___  _| |_
 |    // _ \| | | | __/ _ \ '__|`--. \ '_ \| |/ _ \| | __|
 | |\ \ (_) | |_| | ||  __/ |  /\__/ / |_) | | (_) | | |_
 \_| \_\___/ \__,_|\__\___|_|  \____/| .__/|_|\___/|_|\__|
                                     | |
        IoT Exploitation Framework   |_|

 Dev Team : Marcin Bury (lucyoa) & Mariusz Kupidura (fwkz)
 Codename : Bad Blood
 Version  : 2.2.1

 Exploits: {exploits_count} Scanners: {scanners_count} Creds: {creds_count} Payloads: {payloads_count}
""".format(exploits_count=self.modules_count['exploits'],
           scanners_count=self.modules_count['scanners'],
           creds_count=self.modules_count['creds'],
           payloads_count=self.modules_count['payloads'])

    def __parse_prompt(self):
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        raw_prompt_template = os.getenv("RSF_RAW_PROMPT", raw_prompt_default_template).replace('\\033', '\033')
        self.raw_prompt_template = raw_prompt_template if '{host}' in raw_prompt_template else raw_prompt_default_template

        module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[91m\002{module}\001\033[0m\002) > "
        module_prompt_template = os.getenv("RSF_MODULE_PROMPT", module_prompt_default_template).replace('\\033', '\033')
        self.module_prompt_template = module_prompt_template if all(map(lambda x: x in module_prompt_template, ['{host}', "{module}"])) else module_prompt_default_template

    def _extend_with_global_commands(self, sequence):
        """ Extend specific command suggestion with global commands """
        sequence.extend(self.global_commands)
        sequence.sort()
        return sequence

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
        if self.current_module and GLOBAL_OPTS:
            return sorted(itertools.chain(self.module_commands, ('unsetg ',)))
        elif self.current_module and isinstance(self.current_module, Exploit):
            return self.module_commands
        elif self.current_module and isinstance(self.current_module,
                                                BasePayload):
            return self.payload_commands
        elif self.current_module:
            return self.module_commands
        else:
            return self.global_commands

    def command_back(self, *args, **kwargs):
        self.current_module = None

    def command_use(self, module_path, *args, **kwargs):
        module_path = utils.pythonize_path(module_path)
        module_path = '.'.join(('routersploit', 'modules', module_path))
        # module_path, _, exploit_name = module_path.rpartition('.')
        try:
            self.current_module = utils.import_exploit(module_path)()
        except RoutersploitException as err:
            utils.print_error(err.message)

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
        except KeyboardInterrupt:
            utils.print_info()
            utils.print_error("Operation cancelled by user")
        except Exception:
            utils.print_error(traceback.format_exc(sys.exc_info()))

    def command_exploit(self, *args, **kwargs):
        self.command_run()

    @utils.module_required
    def command_set(self, *args, **kwargs):
        key, _, value = args[0].partition(' ')
        if key in self.current_module.options:
            setattr(self.current_module, key, value)
            if kwargs.get("glob", False):
                GLOBAL_OPTS[key] = value
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
    def command_setg(self, *args, **kwargs):
        kwargs['glob'] = True
        self.command_set(*args, **kwargs)

    @utils.stop_after(2)
    def complete_setg(self, text, *args, **kwargs):
        return self.complete_set(text, *args, **kwargs)

    @utils.module_required
    def command_unsetg(self, *args, **kwargs):
        key, _, value = args[0].partition(' ')
        try:
            del GLOBAL_OPTS[key]
        except KeyError:
            utils.print_error("You can't unset global option '{}'.\n"
                              "Available global options: {}".format(key, GLOBAL_OPTS.keys()))
        else:
            utils.print_success({key: value})

    @utils.stop_after(2)
    def complete_unsetg(self, text, *args, **kwargs):
        if text:
            return [' '.join((attr, "")) for attr in GLOBAL_OPTS.keys() if attr.startswith(text)]
        else:
            return GLOBAL_OPTS.keys()

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
    def _show_info(self, *args, **kwargs):
        utils.pprint_dict_in_order(
            self.module_metadata,
            ("name", "description", "devices", "authors", "references"),
        )
        utils.print_info()

    @utils.module_required
    def _show_options(self, *args, **kwargs):
        target_opts = ['target', 'port', 'rhost', 'rport', 'lhost', 'lport']
        module_opts = [opt for opt in self.current_module.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        utils.print_info('\nTarget options:')
        utils.print_table(headers, *self.get_opts(*target_opts))

        if module_opts:
            utils.print_info('\nModule options:')
            utils.print_table(headers, *self.get_opts(*module_opts))

        utils.print_info()

    @utils.module_required
    def _show_devices(self, *args, **kwargs):  # TODO: cover with tests
        try:
            devices = self.current_module._Exploit__info__['devices']

            utils.print_info("\nTarget devices:")
            i = 0
            for device in devices:
                if isinstance(device, dict):
                    utils.print_info("   {} - {}".format(i, device['name']))
                else:
                    utils.print_info("   {} - {}".format(i, device))
                i += 1
            utils.print_info()
        except KeyError:
            utils.print_info("\nTarget devices are not defined")

    def __show_modules(self, root=''):
        for module in [module for module in self.modules if module.startswith(root)]:
            utils.print_info(module.replace('.', os.sep))

    def _show_all(self, *args, **kwargs):
        self.__show_modules()

    def _show_scanners(self, *args, **kwargs):
        self.__show_modules('scanners')

    def _show_exploits(self, *args, **kwargs):
        self.__show_modules('exploits')

    def _show_creds(self, *args, **kwargs):
        self.__show_modules('creds')

    def command_show(self, *args, **kwargs):
        sub_command = args[0]
        try:
            getattr(self, "_show_{}".format(sub_command))(*args, **kwargs)
        except AttributeError:
            utils.print_error("Unknown 'show' sub-command '{}'. "
                              "What do you want to show?\n"
                              "Possible choices are: {}".format(sub_command, self.show_sub_commands))

    @utils.stop_after(2)
    def complete_show(self, text, *args, **kwargs):
        if text:
            return [command for command in self.show_sub_commands if command.startswith(text)]
        else:
            return self.show_sub_commands

    @utils.module_required
    def command_check(self, *args, **kwargs):
        try:
            result = self.current_module.check()
        except Exception as error:
            utils.print_error(error)
        else:
            if result is True:
                utils.print_success("Target is vulnerable")
            elif result is False:
                utils.print_error("Target is not vulnerable")
            else:
                utils.print_status("Target could not be verified")

    def command_help(self, *args, **kwargs):
        utils.print_info(self.global_help)
        if self.current_module:
            utils.print_info("\n", self.module_help)

    def command_exec(self, *args, **kwargs):
        os.system(args[0])

    def command_search(self, *args, **kwargs):
        keyword = args[0]

        if not keyword:
            utils.print_error("Please specify search keyword. e.g. 'search cisco'")
            return

        for module in self.modules:
            if keyword in module:
                module = utils.humanize_path(module)
                utils.print_info(
                    "{}\033[31m{}\033[0m{}".format(*module.partition(keyword))
                )

    def command_exit(self, *args, **kwargs):
        raise EOFError
