from flask import Response
from routersploit.modules.exploits.routers.multi.misfortune_cookie import Exploit


def apply_response(*args, **kwargs):
    resp = Response("TEST omg1337hax TEST", status=404)
    resp.headers["server"] = "RomPager"
    return resp


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/test", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.device == ""

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
