from unittest import mock
from routersploit.modules.exploits.routers.netcore.udp_53413_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.netcore.udp_53413_rce.shell")
def test_check_success1(mocked_shell, udp_target):
    """ Test scenario - successful check """

    command_mock = udp_target.get_command_mock(b"\x00" * 8)
    command_mock.return_value = b"\xD0\xA5Login:"

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 53413

    exploit.target = udp_target.host
    exploit.port = udp_target.port

    assert exploit.check()
    assert exploit.run() is None


@mock.patch("routersploit.modules.exploits.routers.netcore.udp_53413_rce.shell")
def test_check_success2(mocked_shell, udp_target):
    """ Test scenario - successful check """

    command_mock = udp_target.get_command_mock(b"\x00" * 8)
    command_mock.return_value = b"\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x01\x00\x00"

    exploit = Exploit()

    exploit.target = udp_target.host
    exploit.port = udp_target.port

    assert exploit.check()
    assert exploit.run() is None
