import time
from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.multi.gpon_home_gateway_rce import Exploit


mark = ""
first_req = 0


def apply_response1(*args, **kwargs):
    global mark, first_req

    first_req = time.time()
    mark = request.form["dest_host"]
    return "Test", 200


def apply_response_without_waiting(*args, **kwargs):
    global mark, first_req

    response = "diag_result = \"{}\\nNo traceroute test.".format(mark)
    return response, 200


def apply_response_with_waiting(*args, **kwargs):
    global mark, first_req

    response = "diag_result = \"{}\\nNo traceroute test.".format(mark)

    if time.time() - first_req > 3:
        return response, 200
    else:
        return "diag_result = \"\\nNo traceroute test.", 200


@mock.patch("routersploit.modules.exploits.routers.multi.gpon_home_gateway_rce.shell")
def test_check_success1(mocked_shell, target):
    """ Test scenario - successful check without waiting """

    route_mock1 = target.get_route_mock("/GponForm/diag_Form", methods=["POST"])
    route_mock1.side_effect = apply_response1

    route_mock2 = target.get_route_mock("/diag.html", methods=["GET"])
    route_mock2.side_effect = apply_response_without_waiting

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 8080

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None


@mock.patch("routersploit.modules.exploits.routers.multi.gpon_home_gateway_rce.shell")
def test_check_success2(mocked_shell, target):
    """ Test scenario - successful check with waiting """

    route_mock1 = target.get_route_mock("/GponForm/diag_Form", methods=["POST"])
    route_mock1.side_effect = apply_response1

    route_mock2 = target.get_route_mock("/diag.html", methods=["GET"])
    route_mock2.side_effect = apply_response_with_waiting

    exploit = Exploit()

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
