from unittest import mock
from routersploit.modules.exploits.routers.dlink.dwr_932b_backdoor import Exploit


@mock.patch("routersploit.modules.exploits.routers.dlink.dwr_932b_backdoor.shell")
def test_check_success(mocked_shell, udp_target):
    """ Test scenario - successful check """

    command_mock = udp_target.get_command_mock(b"HELODBG")
    command_mock.return_value = b"TEST Hello TEST"

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 39889

    exploit.target = udp_target.host
    exploit.port = udp_target.port

    assert exploit.check()
    assert exploit.run() is None
