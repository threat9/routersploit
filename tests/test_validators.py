import unittest

import mock

from routersploit import validators
from routersploit.exceptions import OptionValidationError
from tests.test_case import RoutersploitTestCase


class ValidatorsTest(RoutersploitTestCase):
    def test_url_adding_http_prefix(self):
        self.assertEqual(validators.url("127.0.0.1"), "http://127.0.0.1")

    def test_url_already_with_http_prefix(self):
        self.assertEqual(validators.url("http://127.0.0.1"),
                         "http://127.0.0.1")

    def test_url_already_with_https_prefix(self):
        self.assertEqual(validators.url("https://127.0.0.1"),
                         "https://127.0.0.1")

    def test_ipv4_valid_address(self):
        address = "127.0.0.1"
        self.assertEqual(validators.ipv4(address), address)

    def test_ipv4_invalid_address_1(self):
        """ IP address with segment out of range. """
        address = "127.256.0.1"
        with self.assertRaises(OptionValidationError):
            validators.ipv4(address)

    def test_ipv4_invalid_address_2(self):
        """ IP address with 4 digit segment. """
        address = "127.0.0.1234"
        with self.assertRaises(OptionValidationError):
            validators.ipv4(address)

    def test_ipv4_invalid_address_3(self):
        """ IP address with extra segment """
        address = "127.0.0.123.123"
        with self.assertRaises(OptionValidationError):
            validators.ipv4(address)

    @mock.patch("socket.inet_pton")
    def test_ipv4_no_inet_pton_valid_address(self, mock_inet_pton):
        address = "127.0.0.1"
        mock_inet_pton.side_effect = AttributeError
        self.assertEqual(validators.ipv4(address), "127.0.0.1")

    @mock.patch("socket.inet_pton")
    def test_ipv4_no_inet_pton_invalid_address_1(self, mock_inet_pton):
        """ IP address with segment out of range. """
        address = "127.256.0.1"
        mock_inet_pton.side_effect = AttributeError
        with self.assertRaises(OptionValidationError):
            validators.ipv4(address)

    @mock.patch("socket.inet_pton")
    def test_ipv4_no_inet_pton_invalid_address_2(self, mock_inet_pton):
        """ IP address with 4 digit segment. """
        address = "127.0.0.1234"
        mock_inet_pton.side_effect = AttributeError
        with self.assertRaises(OptionValidationError):
            validators.ipv4(address)

    @mock.patch("socket.inet_pton")
    def test_ipv4_no_inet_pton_invalid_address_3(self, mock_inet_pton):
        """ IP address with extra segment """
        address = "127.0.0.123.123"
        mock_inet_pton.side_effect = AttributeError
        with self.assertRaises(OptionValidationError):
            validators.ipv4(address)

    def test_address_strip_scheme_1(self):
        address = "http://127.0.0.1"
        self.assertEqual(validators.address(address), "127.0.0.1")

    def test_address_strip_scheme_2(self):
        address = "ftp://127.0.0.1"
        self.assertEqual(validators.address(address), "127.0.0.1")

    def test_boolify_false_1(self):
        value = False
        self.assertEqual(validators.boolify(value), False)

    def test_boolify_false_2(self):
        value = "No"
        self.assertEqual(validators.boolify(value), False)

    def test_boolify_false_3(self):
        value = "n"
        self.assertEqual(validators.boolify(value), False)

    def test_boolify_false_4(self):
        value = "OFF"
        self.assertEqual(validators.boolify(value), False)

    def test_boolify_false_5(self):
        value = "0"
        self.assertEqual(validators.boolify(value), False)

    def test_boolify_false_6(self):
        value = "False"
        self.assertEqual(validators.boolify(value), False)

    def test_boolify_false_7(self):
        value = "f"
        self.assertEqual(validators.boolify(value), False)

    def test_boolify_true_1(self):
        value = True
        self.assertEqual(validators.boolify(value), True)

    def test_boolify_true_2(self):
        value = "Yes"
        self.assertEqual(validators.boolify(value), True)

    def test_boolify_true_3(self):
        value = "y"
        self.assertEqual(validators.boolify(value), True)

    def test_boolify_true_4(self):
        value = "oN"
        self.assertEqual(validators.boolify(value), True)

    def test_boolify_true_5(self):
        value = "1"
        self.assertEqual(validators.boolify(value), True)

    def test_boolify_true_6(self):
        value = "tRuE"
        self.assertEqual(validators.boolify(value), True)

    def test_boolify_true_7(self):
        value = "t"
        self.assertEqual(validators.boolify(value), True)

    def test_choice_1(self):
        valid_values = ["test1", "test2"]
        selected_value = "test1"
        self.assertEqual(validators.choice(valid_values)(selected_value),
                         selected_value)

    def test_choice_2(self):
        valid_values = ["test1", "test2"]
        selected_value = "t"

        with self.assertRaises(OptionValidationError):
            validators.choice(valid_values)(selected_value)

    def test_choice_3(self):
        valid_values = ["test1", "test2"]
        selected_value = "Test1"

        with self.assertRaises(OptionValidationError):
            validators.choice(valid_values)(selected_value)

    def test_integer_1(self):
        self.assertEqual(validators.integer('1'), 1)

    def test_integer_2(self):
        self.assertEqual(validators.integer('123'), 123)

    def test_integer_3(self):
        with self.assertRaises(OptionValidationError):
            validators.integer('foobar')


if __name__ == '__main__':
    unittest.main()
