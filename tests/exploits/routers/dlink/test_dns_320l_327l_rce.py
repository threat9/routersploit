from unittest import mock
import re
from flask import request
from routersploit.modules.exploits.routers.dlink.dns_320l_327l_rce import Exploit


def apply_response(*args, **kwargs):
    inj = request.args["f_gaccount"]
    res = re.findall(r"\$\(\((.*-1)\)\)", inj)
    data = "TEST"
    if res:
        solution = eval(res[0], {'__builtins__': None})
        data += str(solution)

    return data, 200


@mock.patch("routersploit.modules.exploits.routers.dlink.dns_320l_327l_rce.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/cgi-bin/gdrive.cgi", methods=["GET"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
