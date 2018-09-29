from unittest import mock
from routersploit.modules.exploits.routers.zyxel.p660hn_t_v1_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.zyxel.p660hn_t_v1_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/cgi-bin/authorize.asp", methods=["GET"])
    route_mock.return_value = (
        "TEST"
        "ZyXEL P-660HN-T1A"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
