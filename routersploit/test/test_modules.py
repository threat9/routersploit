from inspect import getmodule
from itertools import chain
from unittest import main, TestCase, TestSuite

from routersploit.exploits import Exploit
from routersploit.interpreter import RoutersploitInterpreter


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
            "targets",
            "authors",
            "references"])

        self.assertTrue(set(self.metadata.keys()).issubset(legal_keys))


def load_tests(loader, tests, pattern):
    """Map every module to a test case, and group them into a suite."""

    def tests():

        # let interpreter load the modules
        interpreter = RoutersploitInterpreter()

        for module_path in interpreter.modules:

            # use the given module
            interpreter.command_use(module_path)

            class ParametrizedModuleTest(ModuleTest):

                # bind module and metadata
                module = interpreter.current_module
                metadata = interpreter.module_metadata

                def shortDescription(self):
                    # provide the module name in the test description
                    return getmodule(self.module).__name__

            # yield the tests from this test case
            yield loader.loadTestsFromTestCase(ParametrizedModuleTest)

    suite = TestSuite()
    suite.addTests(chain(*tests()))
    return suite

if __name__ == '__main__':
    main()
