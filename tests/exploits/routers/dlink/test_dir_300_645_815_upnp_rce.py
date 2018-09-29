from unittest import mock
from routersploit.modules.exploits.routers.dlink.dir_300_645_815_upnp_rce import Exploit


@mock.patch("routersploit.modules.exploits.routers.dlink.dir_300_645_815_upnp_rce.shell")
def test_check_success(mocked_shell, udp_target):
    """ Test scenario - successful check """

    request = (
        b"M-SEARCH * HTTP/1.1\r\n"
        b"Host:239.255.255.250:1900\r\n"
        b"ST:upnp:rootdevice\r\n"
        b"Man:\"ssdp:discover\"\r\n"
        b"MX:2\r\n\r\n"
    )

    command_mock = udp_target.get_command_mock(request)
    command_mock.return_value = b"Linux, UPnP/1.0, DIR-1234"

    exploit = Exploit()

    assert exploit.target == ""
    assert exploit.port == 1900

    exploit.target = udp_target.host
    exploit.port = udp_target.port

    assert exploit.check()
    assert exploit.run() is None
