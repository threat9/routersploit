from flask import request, Response
from base64 import b64decode
from routersploit.modules.exploits.cameras.brickcom.users_cgi_creds_disclosure import Exploit


response = (
    """
    size=4
    User1.index=1
    User1.username=admin
    User1.password=test1234
    User1.privilege=1

    User2.index=2
    User2.username=viewer
    User2.password=viewer
    User2.privilege=0

    User3.index=3
    User3.username=rviewer
    User3.password=rviewer
    User3.privilege=2

    User4.index=0
    User4.username=visual
    User4.password=visual1234
    User4.privilege=0
    """
)


def apply_response(*args, **kwargs):
    if "Authorization" in request.headers.keys():
        creds = str(b64decode(request.headers["Authorization"].replace("Basic ", "")), "utf-8")

        if creds in ["rviewer:rviewer"]:
            return response, 200

    resp = Response("Unauthorized")
    resp.headers["WWW-Authenticate"] = "Basic ABC"
    return resp, 401


def test_check_success(target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/cgi-bin/users.cgi", methods=["GET", "POST"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is True
    assert exploit.run() is None
