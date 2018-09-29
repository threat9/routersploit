from unittest import mock
from flask import request
from routersploit.modules.exploits.routers.zte.f460_f660_backdoor import Exploit


def apply_response(*args, **kwargs):
    cmd = request.form['Cmd']
    res = '<textarea cols="" rows="" id="Frm_CmdAck" class="textarea_1">' + cmd + '</textarea>'
    return res, 200


@mock.patch("routersploit.modules.exploits.routers.zte.f460_f660_backdoor.shell")
def test_check_success(mocked_shell, target):
    """ Test scenario - successful check """

    route_mock = target.get_route_mock("/web_shell_cmd.gch", methods=["POST"])
    route_mock.side_effect = apply_response

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
