## Description

Module sends M-SEARCH request to target and retrieve information from UPnP enabled systems.

## Verification Steps

  1. Start `./rsf.py`
  2. Do: `use generic/upnp/ssdp_msearch`
  3. Do: `set target [TargetIP]`
  4. Do: `run`
  5. If target supports UPnP information are retrieved.

## Scenarios

```
rsf > use generic/upnp/ssdp_msearch
rsf (SSDP M-SEARCH Info Discovery) > set target 192.168.1.1
[+] target => 192.168.1.1
rsf (SSDP M-SEARCH Info Discovery) > run
[*] Running module...
[*] 192.168.1.1:1900 | Custom/1.0 UPnP/1.0 Proc/Ver | http://192.168.1.1:5431/dyndev/uuid:ec2280e5-e804-04e8-e580-22ec22e50400 | uuid:ec2280e5-e804-04e8-e580-22ec22e50400::upnp:rootdevice
```
