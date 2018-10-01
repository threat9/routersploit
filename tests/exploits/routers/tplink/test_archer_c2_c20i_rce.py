from unittest import mock
from routersploit.modules.exploits.routers.tplink.archer_c2_c20i_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.tplink.archer_c2_c20i_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/cgi", methods=["POST"])
    route_mock.return_value = (
        "TEST"
        "[error]0"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
