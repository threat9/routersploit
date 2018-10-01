from unittest import mock
from routersploit.modules.exploits.routers.dlink.dir_815_850l_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.dlink.dir_815_850l_rce.shell")
def test_check_success(mocked_shell, udp_target):
    """ Test scenario - successful check """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 1900

    exploit.target = udp_target.host
    exploit.port = udp_target.port

    assert exploit.check() is None
    assert exploit.run() is None
