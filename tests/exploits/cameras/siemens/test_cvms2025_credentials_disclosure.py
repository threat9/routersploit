from routersploit.modules.exploits.cameras.siemens.cvms2025_credentials_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/cgi-bin/readfile.cgi", methods=["GET"])
    route_mock.return_value = (
        'Adm_ID="admin"'
    )

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
