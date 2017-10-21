import unittest

import mock

from routersploit import utils
from tests.test_case import RoutersploitTestCase


class UtilsTest(RoutersploitTestCase):
    @mock.patch('os.walk')
    def test_load_modules_01(self, mock_walk):
        mock_walk.return_value = (
            ('/Abs/Path/routersploit/routersploit/modules', ['asmax', 'creds'],
             ['__init__.py', '__init__.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/creds', [],
             ['__init__.py', '__init__.pyc', 'ftp_bruteforce.py',
              'ftp_bruteforce.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/exploits/asmax', [],
             ['__init__.py', '__init__.pyc', 'asmax_exploit.py',
              'asmax_exploit.pyc']),
        )

        path = 'path/to/module'
        modules = utils.index_modules(path)

        mock_walk.assert_called_once_with(path)
        self.assertEqual(
            modules,
            [
                'creds.ftp_bruteforce',
                'exploits.asmax.asmax_exploit'
            ]
        )

    @mock.patch('os.walk')
    def test_load_modules_import_error_02(self, mock_walk):
        mock_walk.return_value = (
            ('/Abs/Path/routersploit/routersploit/modules', ['asmax', 'creds'],
             ['__init__.py', '__init__.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/creds', [],
             ['__init__.py', '__init__.pyc', 'ftp_bruteforce.py',
              'ftp_bruteforce.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/exploits/asmax', [],
             ['__init__.py', '__init__.pyc', 'asmax_exploit.py',
              'asmax_exploit.pyc', 'asmax_multi.py', 'asmax_multi.pyc']),
        )

        path = 'path/to/module'
        modules = utils.index_modules(path)

        mock_walk.assert_called_once_with(path)

        self.assertEqual(
            modules,
            [
                'creds.ftp_bruteforce',
                'exploits.asmax.asmax_exploit',
                'exploits.asmax.asmax_multi',
            ]
        )

    @mock.patch('routersploit.utils.print_info')
    def test_print_table_01(self, mock_print):
        utils.print_table(
            ["Name", "Value", "Description"],
            ('foo', 'bar', 'baz'),
            (1, 2, 3),
            ("port", 80, "port number")
        )
        self.assertEqual(
            mock_print.mock_calls,
            [
                mock.call(),
                mock.call('   Name     Value     Description     '),
                mock.call('   ----     -----     -----------     '),
                mock.call('   foo      bar       baz             '),
                mock.call('   1        2         3               '),
                mock.call('   port     80        port number     '),
                mock.call()
            ]
        )

    @mock.patch('routersploit.utils.print_info')
    def test_print_table_02(self, mock_print):
        utils.print_table(
            ["Name", "Value", "Description"],
        )
        self.assertEqual(
            mock_print.mock_calls,
            [
                mock.call(),
                mock.call('   Name     Value     Description     '),
                mock.call('   ----     -----     -----------     '),
                mock.call()
            ]
        )


if __name__ == '__main__':
    unittest.main()
