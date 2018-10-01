from routersploit.modules.exploits.cameras.honeywell.hicc_1100pt_password_disclosure import Exploit


def test_success(target):
    """ Test scenario: successful check """

    route_mock = target.get_route_mock("/cgi-bin/readfile.cgi", methods=["GET"])
    route_mock.return_value = (
        'var Adm_ID="admin";'
        'var Adm_Pass1="admin";'
        'var Adm_Pass2="admin";'
        'var Language="en";'
        'var Logoff_Time="0";'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
