from flask import Response
from routersploit.modules.exploits.routers.tplink.wdr842nd_wdr842n_configure_disclosure import Exploit


def apply_response(*args, **kwargs):
    resp = Response("TEST", status=200)
    resp.headers['Content-Type'] = 'x-bin/octet-stream'
    return resp


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/config.bin", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
