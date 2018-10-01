from routersploit.modules.exploits.cameras.multi.dvr_creds_disclosure import Exploit


def test_check_success(target):
    """ Test scenario - successful exploitation """

    route_mock = target.get_route_mock("/device.rsp", methods=["GET"])
    route_mock.return_value = ("""{"result":0,"list":[{"uid":"admin","pwd":"admin","role":2,"enmac":0,"mac":"00:00:00:00:00:00","playback":4294967295,"view":4294967295,"rview":4294967295,"ptz":4294967295,"backup":4294967295,"opt":4294967295},{"uid":"test","pwd":"test","role":3,"enmac":0,"mac":"00:11:22:33:44:55","playback":65535,"view":0,"rview":65535,"ptz":0,"backup":65535,"opt":62437}]}""")

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 80

    exploit.target = target.host
    exploit.port = target.port

    assert exploit.check()
    assert exploit.run() is None
