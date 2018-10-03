from unittest import mock
from routersploit.modules.exploits.routers.dlink.dcs_930l_auth_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.dlink.dcs_930l_auth_rce.shell")
def test_exploit_success(mocked_shell, target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/setSystemCommand", methods=["POST"])
    route_mock.return_value = (
        "TEST"
        "ConfigSystemCommand"
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.username == "admin"
    assert exploit.password == ""

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
