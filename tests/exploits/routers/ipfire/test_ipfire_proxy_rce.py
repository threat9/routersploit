from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.ipfire.ipfire_proxy_rce import Exploit


def apply_response(*args, **kwargs):
    data = request.form["NCSA_PASS"] + "<!DOCTYPE html>"
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.ipfire.ipfire_proxy_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/cgi-bin/proxy.cgi", methods=["POST"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 444
    assert exploit.ssl is True
    assert exploit.username == "admin"
    assert exploit.password == "admin"

    exploit.target = target.host
    exploit.port = target.port
    exploit.ssl = "false"

    assert exploit.check()
    assert exploit.run() is None
