from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.linksys.wap54gv3_rce import Exploit


def apply_response(*args, **kwargs):
    data = "TEST<textarea rows=30 cols=100>" + request.form["data1"] + "</textarea>TEST"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.linksys.wap54gv3_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/debug.cgi", methods=["POST"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
