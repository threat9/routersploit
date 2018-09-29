from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.tplink.wdr740nd_wdr740n_backdoor import Exploit


def apply_response(*args, **kwargs):
    cmd = request.args["cmd"]
    data = 'TEST; var cmdResult = new Array(\n"' + cmd + '",\n0,0 ); TEST'
    return data, 200


@mock.patch("routersploit.modules.exploits.routers.tplink.wdr740nd_wdr740n_backdoor.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/userRpm/DebugResultRpm.htm", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.username == "admin"
    assert exploit.password == "admin"

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
