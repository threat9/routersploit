import unittest
import os

import pexpect

from routersploit.test import RoutersploitTestCase


class RoutersploitCompleterTest(RoutersploitTestCase):

    def __init__(self, methodName='runTest'):
        super(RoutersploitCompleterTest, self).__init__(methodName)
        self.cli_path = os.path.abspath(os.path.join(__file__, os.pardir, os.pardir, os.pardir, 'rsf.py'))
        self.raw_prompt = "\033[4mrsf\033[0m > "
        self.module_prompt = lambda x: "\033[4mrsf\033[0m (\033[91m{}\033[0m) > ".format(x)

    def setUp(self):
        self.rsf = pexpect.spawn('python {}'.format(self.cli_path))
        self.rsf.send('\r\n')
        self.assertPrompt(self.raw_prompt)

    def tearDown(self):
        self.rsf.terminate(force=True)

    def assertPrompt(self, *args):
        value = ''.join(args)
        self.rsf.expect_exact(value, timeout=1)

    def set_module(self):
        self.rsf.send("use creds/ftp_bruteforce\r\n")
        self.assertPrompt(self.module_prompt('FTP Bruteforce'))

    def test_raw_commands_no_module(self):
        self.rsf.send("\t\t")
        self.assertPrompt('exec   exit   help   show   use    \r\n', self.raw_prompt)

    def test_complete_use_raw(self):
        self.rsf.send("u\t\t")
        self.assertPrompt(self.raw_prompt, 'use ')

    def test_complete_use(self):
        self.rsf.send("use \t\t")
        self.assertPrompt(
            'creds     exploits  scanners  \r\n',
            self.raw_prompt,
            'use '
        )

    def test_complete_use_creds(self):
        self.rsf.send("use cr\t\t")
        self.assertPrompt(
            self.raw_prompt,
            'use creds/'
        )

    def test_complete_use_creds_2(self):
        self.rsf.send("use creds/\t\t")
        self.assertPrompt(
            'creds/http_basic_default'
        )

    def test_complete_use_exploits(self):
        self.rsf.send("use ex\t\t")
        self.assertPrompt(
            self.raw_prompt,
            'use exploits/'
        )

    def test_complete_use_exploits_2(self):
        self.rsf.send("use exploits/\t\t")
        self.assertPrompt(
            'exploits/dlink/'
        )

    def test_complete_use_exploits_3(self):
        self.rsf.send("use exploits/dli\t")
        self.assertPrompt(
            self.raw_prompt,
            'use exploits/dlink/'
        )

    def test_complete_use_exploits_4(self):
        self.rsf.send("use exploits/dlink/dir_300_320_\t\t\t")
        self.assertPrompt(
            'exploits/dlink/dir_300_320_615_auth_bypass'
        )

    def test_raw_commands_with_module(self):
        self.set_module()
        self.rsf.send("\t\t")
        self.assertPrompt(
            '  exec   exit   help   run    set    setg   show   use    \r\n',
            self.module_prompt('FTP Bruteforce')
        )

    def test_complete_back_raw(self):
        self.set_module()
        self.rsf.send("b\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'back'
        )

    def test_complete_check_raw(self):
        self.set_module()
        self.rsf.send("c\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'check'
        )

    def test_complete_run_raw(self):
        self.set_module()
        self.rsf.send("r\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'run'
        )

    def test_complete_set_raw(self):
        self.set_module()
        self.rsf.send("s\t\t")
        self.assertPrompt(
            'set    setg   show   \r\n',
            self.module_prompt('FTP Bruteforce')
        )

    def test_complete_set_raw_2(self):
        self.set_module()
        self.rsf.send("se\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'se\at',
        )

    def test_complete_set_raw_3(self):
        self.set_module()
        self.rsf.send("set\t\t")
        self.assertPrompt(
            'set    setg   \r\n',
            self.module_prompt('FTP Bruteforce'),
        )

    def test_complete_set(self):
        self.set_module()
        self.rsf.send("set \t\t")
        self.assertPrompt(
            'passwords        stop_on_success  threads          verbosity\r\nport             target           usernames        \r\n',
            self.module_prompt('FTP Bruteforce'),
            'set ',
        )

    def test_complete_set_2(self):
        self.set_module()
        self.rsf.send("set u\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'set usernames ',
        )

    def test_complete_setg(self):
        self.set_module()
        self.rsf.send("setg \t\t")
        self.assertPrompt(
            'passwords        stop_on_success  threads          verbosity\r\nport             target           usernames        \r\n',
            self.module_prompt('FTP Bruteforce'),
            'setg ',
        )

    def test_complete_setg_2(self):
        self.set_module()
        self.rsf.send("setg u\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'setg usernames ',
        )

    def test_complete_unsetg(self):
        """
        Not present in completion if no global option is set
        """
        self.set_module()
        self.rsf.send("\t\t")
        self.assertPrompt(
            "  exec   exit   help   run    set    setg   show   use    \r\n",
            self.module_prompt('FTP Bruteforce'),
        )

    def test_complete_unsetg_2(self):
        """
        Available only when global options is set
        """
        self.set_module()
        self.rsf.send("setg target foo\r\n")
        self.rsf.send("\t\t")
        self.assertPrompt(
            '  use      \r\ncheck    exit     run      setg     unsetg   \r\n',
            self.module_prompt('FTP Bruteforce'),
        )

    def test_complete_unsetg_3(self):
        """
        Testing presence of available options
        """
        self.set_module()
        self.rsf.send("setg target foo\r\n")
        self.rsf.send("setg port bar\r\n")
        self.rsf.send("unsetg \t\t")
        self.assertPrompt(
            "port    target  \r\n",
            self.module_prompt('FTP Bruteforce'),
        )

    def test_complete_unsetg_4(self):
        """
        Testing presence of available options
        """
        self.set_module()
        self.rsf.send("setg target foo\r\n")
        self.rsf.send("unsetg t\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            "unsetg target"
        )

    def test_complete_show_raw(self):
        self.set_module()
        self.rsf.send("sh\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'show ',
        )

    def test_complete_show(self):
        self.set_module()
        self.rsf.send("show \t\t")
        self.assertPrompt(
            'all       creds     devices   exploits  info      options   scanners\r\n',
            self.module_prompt('FTP Bruteforce')
        )

    def test_complete_show_info(self):
        self.set_module()
        self.rsf.send("show i\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'show info'
        )

    def test_complete_show_options(self):
        self.set_module()
        self.rsf.send("show o\t\t")
        self.assertPrompt(
            self.module_prompt('FTP Bruteforce'),
            'show options'
        )

if __name__ == '__main__':
    unittest.main()
