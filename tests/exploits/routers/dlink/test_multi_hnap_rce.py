from unittest import mock
from routersploit.modules.exploits.routers.dlink.multi_hnap_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.dlink.multi_hnap_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/HNAP1/", methods=["GET"])
    route_mock.return_value = (
        "TEST"
        "SOAPActions"
        "TEST"
        "D-Link"
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
