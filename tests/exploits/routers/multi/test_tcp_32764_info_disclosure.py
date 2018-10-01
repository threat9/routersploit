from routersploit.modules.exploits.routers.multi.tcp_32764_info_disclosure import Exploit


def test_check_success1(tcp_target):
    """ Test scenario - successful check Big Endian"""

    command_mock = tcp_target.get_command_mock(b"ABCDE")
    command_mock.return_value = b"MMcS"

    exploit = Exploit()

    assert exploit.target in ["", "127.0.0.1"]
    assert exploit.port == 32764

    exploit.target = tcp_target.host
    exploit.port = tcp_target.port

    assert exploit.check()
    assert exploit.run() is None


def test_check_success2(tcp_target):
    """ Test scenario - successful check - Little Endian"""

    command_mock = tcp_target.get_command_mock(b"ABCDE")
    command_mock.return_value = b"ScMM"

    exploit = Exploit()

    exploit.target = tcp_target.host
    exploit.port = tcp_target.port

    assert exploit.check()
    assert exploit.run() is None
