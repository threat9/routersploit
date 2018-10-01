from flask import request, Response
from base64 import b64decode
from routersploit.modules.creds.cameras.axis.webinterface_http_auth_default_creds import Exploit


def apply_response(*args, **kwargs):
    if "Authorization" in request.headers.keys():
        creds = str(b64decode(request.headers["Authorization"].replace("Basic ", "")), "utf-8")

        if creds in ["root:pass", "root:admin"]:
            return "Authorized", 200

    resp = Response("Unauthorized")
    resp.headers["WWW-Authenticate"] = "Basic ABC"
    return resp, 401


def test_check_success(target):
    """ Test scenario - testing against HTTP server """

    cgi_mock = target.get_route_mock("/", methods=["GET", "POST"])
    cgi_mock.side_effect = apply_response

    exploit = Exploit()
    assert exploit.target == ""
    assert exploit.port == 80
    assert exploit.threads == 1
    assert exploit.defaults == ["root:pass", "root:admin"]
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check() is True
    assert exploit.check_default() is not None
    assert exploit.run() is None
