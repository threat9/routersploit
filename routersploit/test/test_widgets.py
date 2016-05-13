import unittest

try:
    import unittest.mock as mock
except ImportError:
    import mock

from routersploit.test import RoutersploitTestCase
from routersploit import widgets


class WidgetsTest(RoutersploitTestCase):
    def test_url_adding_http_prefix(self):
        self.assertEqual(widgets.url("127.0.0.1"), "http://127.0.0.1")

    def test_url_already_with_http_prefix(self):
        self.assertEqual(widgets.url("http://127.0.0.1"), "http://127.0.0.1")

    def test_url_already_with_https_prefix(self):
        self.assertEqual(widgets.url("https://127.0.0.1"), "https://127.0.0.1")


if __name__ == '__main__':
    unittest.main()
