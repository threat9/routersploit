from unittest import mock
from routersploit.modules.exploits.routers.belkin.play_max_prce import Exploit


@mock.patch("routersploit.modules.exploits.routers.belkin.play_max_prce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/login.stm", methods=["GET"])
    route_mock.return_value = (
        "test"
        "password= \"admin1234\""
        "test"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.cmd == "telnetd"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
