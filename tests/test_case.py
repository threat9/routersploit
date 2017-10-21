import logging
import unittest

from routersploit.utils import NonStringIterable

logging.getLogger().addHandler(logging.NullHandler())


class RoutersploitTestCase(unittest.TestCase):
    def assertIsDecorated(self, function, decorator_name):
        try:
            decorator_list = function.__decorators__
        except AttributeError:
            decorator_list = []

        self.assertIn(
            decorator_name,
            decorator_list,
            msg="'{}' method should be decorated "
                "with 'module_required'".format(function.__name__)
        )

    def assertIsSubset(self, subset, container):
        [self.assertIn(element, container) for element in subset]

    def assertIsSequence(self, arg):
        self.assertEqual(
            True,
            isinstance(arg, NonStringIterable),
            "'{}' is not a sequence".format(arg)
        )
