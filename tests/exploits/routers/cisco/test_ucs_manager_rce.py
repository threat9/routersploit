from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.cisco.ucs_manager_rce import Exploit


def apply_response(*args, **kwargs):
    return (
        "TEST" + request.headers['User-Agent'] + "TEST"
    ), 200


@mock.patch("routersploit.modules.exploits.routers.cisco.ucs_manager_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/ucsm/isSamInstalled.cgi", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
