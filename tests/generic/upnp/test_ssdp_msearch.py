from routersploit.modules.generic.upnp.ssdp_msearch import Exploit


def test_check_success(udp_target):
    """ Test scenario - successful check """

    request = (
        "M-SEARCH * HTTP/1.1\r\n" +
        "HOST: {}:{}\r\n".format(udp_target.host, udp_target.port) +
        "MAN: \"ssdp:discover\"\r\n" +
        "MX: 2\r\n" +
        "ST: upnp:rootdevice\r\n\r\n"
    )
    request = bytes(request, "utf-8")

    response = (
        b"HTTP/1.1 200 OK\r\n"
        b"CACHE-CONTROL: max-age=120\r\n"
        b"ST: upnp:rootdevice\r\n"
        b"USN: uuid:0ef8055a-8850-47b8-ac43-91f41fdd8d83::upnp:rootdevice\r\n"
        b"EXT:\r\n"
        b"SERVER: AsusWRT/3.0.0.4 UPnP/1.1 MiniUPnPd/1.9\r\n"
        b"LOCATION: http://192.168.2.1:48611/rootDesc.xml\r\n"
        b"OPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n"
        b"01-NLS: 1\r\n"
        b"BOOTID.UPNP.ORG: 1\r\n"
        b"CONFIGID.UPNP.ORG: 1337\r\n\r\n"
    )

    command_mock = udp_target.get_command_mock(request)
    command_mock.return_value = response

    exploit = Exploit()
    exploit.target = udp_target.host
    exploit.port = udp_target.port

    assert exploit.run() is None
