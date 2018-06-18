import pytest

from threat9_test_bed.scenarios import HttpScenario
from threat9_test_bed.service_mocks import HttpScenarioService, HttpServiceMock
from threat9_test_bed.scenarios import TelnetScenario
from threat9_test_bed.service_mocks.telnet_service_mock import TelnetServiceMock
from threat9_test_bed.service_mocks.tcp_service_mock import TCPServiceMock
from threat9_test_bed.service_mocks.udp_service_mock import UDPServiceMock


@pytest.fixture
def target():
    with HttpServiceMock("127.0.0.1", 0) as target_:
        yield target_


@pytest.fixture(scope="session")
def empty_target():
    with HttpScenarioService("127.0.0.1", 0,
                             HttpScenario.EMPTY_RESPONSE) as http_service:
        yield http_service


@pytest.fixture(scope="session")
def trash_target():
    with HttpScenarioService("127.0.0.1", 0,
                             HttpScenario.TRASH) as http_service:
        yield http_service


@pytest.fixture(scope="session")
def not_found_target():
    with HttpScenarioService("127.0.0.1", 0,
                             HttpScenario.NOT_FOUND) as http_service:
        yield http_service


@pytest.fixture(scope="session")
def redirect_target():
    with HttpScenarioService("127.0.0.1", 0,
                             HttpScenario.REDIRECT) as http_service:
        yield http_service


@pytest.fixture(scope="session")
def error_target():
    with HttpScenarioService("127.0.0.1", 0,
                             HttpScenario.ERROR) as http_service:
        yield http_service


@pytest.fixture(scope="session")
def timeout_target():
    with HttpScenarioService("127.0.0.1", 0,
                             HttpScenario.TIMEOUT) as http_service:
        yield http_service


@pytest.fixture
def generic_target():
    with TelnetServiceMock("127.0.0.1", 0, TelnetScenario.AUTHORIZED) as telnet_service:
        yield telnet_service


@pytest.fixture
def tcp_target():
    with TCPServiceMock("127.0.0.1", 0) as tcp_service:
        yield tcp_service


@pytest.fixture
def udp_target():
    with UDPServiceMock("127.0.0.1", 0) as udp_service:
        yield udp_service
