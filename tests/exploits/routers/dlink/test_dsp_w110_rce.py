from unittest import mock
from flask import Response
from routersploit.modules.exploits.routers.dlink.dsp_w110_rce import Exploit


def apply_response(*args, **kwargs):
    resp = Response("Test")
    resp.headers['Server'] = 'lighttpd/1.4.34'
    return resp


@mock.patch("routersploit.modules.exploits.routers.dlink.dsp_w110_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
