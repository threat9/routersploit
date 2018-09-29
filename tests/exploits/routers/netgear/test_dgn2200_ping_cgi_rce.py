from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.netgear.dgn2200_ping_cgi_rce import Exploit


def apply_response(*args, **kwargs):
    res = request.form['ping_IPAddr']
    data = "<textarea>\nTEST\n" + res + "\n\nTEST\n</textarea>"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.netgear.dgn2200_ping_cgi_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/ping.cgi", methods=["POST"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.username == "admin"
    assert exploit.password == "password"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
