import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from routersploit.utils import index_modules
from routersploit.test import RoutersploitTestCase


class UtilsTest(RoutersploitTestCase):
    @mock.patch('os.walk')
    def test_load_modules_01(self, mock_walk):
        mock_walk.return_value = (
            ('/Abs/Path/routersploit/routersploit/modules', ['asmax', 'creds'], ['__init__.py', '__init__.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/creds', [], ['__init__.py', '__init__.pyc', 'ftp_bruteforce.py', 'ftp_bruteforce.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/exploits/asmax', [], ['__init__.py', '__init__.pyc', 'asmax_exploit.py', 'asmax_exploit.pyc']),
        )

        path = 'path/to/module'
        modules = index_modules(path)

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
            ('/Abs/Path/routersploit/routersploit/modules', ['asmax', 'creds'], ['__init__.py', '__init__.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/creds', [], ['__init__.py', '__init__.pyc', 'ftp_bruteforce.py', 'ftp_bruteforce.pyc']),
            ('/Abs/Path/routersploit/routersploit/modules/exploits/asmax', [], ['__init__.py', '__init__.pyc', 'asmax_exploit.py', 'asmax_exploit.pyc', 'asmax_multi.py', 'asmax_multi.pyc']),
        )

        path = 'path/to/module'
        modules = index_modules(path)

        mock_walk.assert_called_once_with(path)

        self.assertEqual(
            modules,
            [
                'creds.ftp_bruteforce',
                'exploits.asmax.asmax_exploit',
                'exploits.asmax.asmax_multi',
            ]
        )

if __name__ == '__main__':
    unittest.main()
