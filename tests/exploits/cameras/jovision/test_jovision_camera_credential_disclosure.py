from flask import Response
from routersploit.modules.exploits.cameras.jovision.jovision_credentials_disclosure import Exploit


def apply_response(*args, **kwargs):
    response = (
        """
        [{
            "nIndex":	0,
            "acID":	"admin",
            "acPW":	"admin1234",
            "acDescript":	"admin account",
            "nPower":	20
        }]
        """
    )
    resp = Response(response, status=200)
    resp.headers['Content-Type'] = 'application/json'
    return resp


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock(
        "/cgi-bin/jvsweb.cgi", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is True
    assert exploit.run() is None
