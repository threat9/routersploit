from flask import Response
from routersploit.modules.exploits.routers.netgear.n300_auth_bypass import Exploit


hit = False


def apply_response1(*args, **kwargs):
    global hit
    if hit is False:
        resp = Response("TEST", status=401)
        return resp
    else:
        resp = Response("TEST", status=200)
        return resp


def apply_response2(*args, **kwargs):
    global hit
    hit = True
    return "TEST", 200


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock1 = target.get_route_mock("/", methods=["GET"])
    route_mock1.side_effect = apply_response1

    route_mock2 = target.get_route_mock("/BRS_netgear_success.html", methods=["GET"])
    route_mock2.side_effect = apply_response2

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
