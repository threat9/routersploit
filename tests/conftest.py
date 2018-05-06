import pytest
from unittest.mock import patch

from threat9_test_bed.scenarios import HttpScenario
from threat9_test_bed.service_mocks import HttpScenarioService, HttpServiceMock
from threat9_test_bed.scenarios import TelnetScenario
from threat9_test_bed.service_mocks.telnet_service_mock import TelnetServiceMock

import routersploit.core.exploit.shell


@pytest.fixture
def target():
    with HttpServiceMock("127.0.0.1", 0) as target_:
        yield target_


@pytest.fixture
def generic_target():
    with TelnetServiceMock("127.0.0.1", 0, TelnetScenario.AUTHORIZED) as telnet_service:
        yield telnet_service

