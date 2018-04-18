import unittest

from routersploit.utils import iter_modules
from tests.test_case import RoutersploitTestCase


class ModuleTest(RoutersploitTestCase):
    """A test case that every module must pass.

    Attributes:
        module (Exploit): The exploit instance of the module being tested.
        metadata (Dict): The info associated with the module.
    """

    def __init__(self, methodName='runTest', module=None):
        super(ModuleTest, self).__init__(methodName)
        self.module = module

    def __str__(self):
        return " ".join(
            [super(ModuleTest, self).__str__(), self.module.__module__])

    @property
    def module_metadata(self):
        return getattr(self.module, "_{}__info__".format(self.module.__name__))

    def test_required_metadata(self):
        required_metadata = (
            "name",
            "description",
            "devices",
            "authors",
            "references"
        )
        self.assertIsSubset(required_metadata, self.module_metadata.keys())

    def test_metadata_type(self):
        self.assertIsSequence(self.module_metadata['authors'])
        self.assertIsSequence(self.module_metadata['references'])
        self.assertIsSequence(self.module_metadata['devices'])


def load_tests(loader, tests, pattern):
    """ Map every module to a test case, and group them into a suite. """

    suite = unittest.TestSuite()
    test_names = loader.getTestCaseNames(ModuleTest)
    for module in iter_modules():
        suite.addTests([ModuleTest(name, module) for name in test_names])
    return suite


if __name__ == '__main__':
    unittest.main()
