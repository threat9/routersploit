from routersploit.modules.creds.generic.snmp_bruteforce import Exploit


def test_check_success(generic_target):
    """ Test scenerio - testing against SNMP server """

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 161
    assert exploit.version == 1
    assert exploit.threads == 8
    assert type(exploit.defaults) is list
    assert exploit.stop_on_success is True
    assert exploit.verbosity is True
