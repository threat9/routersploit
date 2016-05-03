from inspect import getmodule
from unittest import main, TestCase, TestSuite

from routersploit.exploits import Exploit
from routersploit.utils import iter_modules


class ModuleTest(TestCase):
    """A test case that every module must pass.

    Attributes:
        module (Exploit): The exploit instance of the module being tested.
        metadata (Dict): The info associated with the module.
    """

    def test_has_exploit(self):
        self.assertIsInstance(self.module, Exploit)

    def test_has_metadata(self):
        self.assertIsInstance(self.metadata, dict)

    def test_legal_metadata_keys(self):

        legal_keys = set([
            "name",
            "description",
            "devices",
            "authors",
            "references"])

        self.assertTrue(set(self.metadata.keys()).issubset(legal_keys))


def load_tests(loader, tests, pattern):
    """Map every module to a test case, and group them into a suite."""

    suite = TestSuite()

    for m in iter_modules():

        class ParametrizedModuleTest(ModuleTest):

            # bind module
            module = m()

            @property
            def metadata(self):
                return getattr(self.module, "_{}__info__".format(self.module.__class__.__name__))

            def shortDescription(self):
                # provide the module name in the test description
                return getmodule(self.module).__name__

        # add the tests from this test case
        suite.addTests(loader.loadTestsFromTestCase(ParametrizedModuleTest))

    return suite

if __name__ == '__main__':
    main()
