import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from routersploit.test import RoutersploitTestCase
from routersploit import validators


class ValidatorsTest(RoutersploitTestCase):
    def test_url_adding_http_prefix(self):
        self.assertEqual(validators.url("127.0.0.1"), "http://127.0.0.1")

    def test_url_already_with_http_prefix(self):
        self.assertEqual(validators.url("http://127.0.0.1"), "http://127.0.0.1")

    def test_url_already_with_https_prefix(self):
        self.assertEqual(validators.url("https://127.0.0.1"), "https://127.0.0.1")


if __name__ == '__main__':
    unittest.main()
