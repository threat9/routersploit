from unittest import mock
from flask import Response
from routersploit.modules.exploits.routers.netgear.r7000_r6400_rce import Exploit


def apply_response(*args, **kwargs):
    resp = Response("TEST", status=401)
    resp.headers["WWW-Authenticate"] = "NETGEAR R7000"
    return resp


@mock.patch("routersploit.modules.exploits.routers.netgear.r7000_r6400_rce.shell")
def test_exploit_success(mocked_shell, target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/", methods=["HEAD"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
