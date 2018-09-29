from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.dlink.multi_hedwig_cgi_exec import Exploit


def apply_response(*args, **kwargs):
    res = request.headers["Cookie"]
    data = "TEST" + res

    return data, 200


@mock.patch("routersploit.modules.exploits.routers.dlink.multi_hedwig_cgi_exec.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    cgi_mock = target.get_route_mock("/hedwig.cgi", methods=["POST"])
    cgi_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
