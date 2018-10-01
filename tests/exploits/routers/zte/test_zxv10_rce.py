from unittest import mock
from routersploit.modules.exploits.routers.zte.zxv10_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.zte.zxv10_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock_v1 = target.get_route_mock("/", methods=["GET"])
    route_mock_v1.return_value = (
        "TEST"
        "Frm_Logintoken\").value = \"(.*)\";"
        "TEST"
    )

    route_mock_v2 = target.get_route_mock("/login.gch", methods=["POST"])
    route_mock_v2.return_value = (
        "TEST"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.username == "root"
    assert exploit.password == "W!n0&oO7."

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
