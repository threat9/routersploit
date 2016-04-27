#!/usr/bin/env python

import os, sys, platform

if os.geteuid() != 0:
	print("%s needs root privildeges\nTry running 'sudo %s'" % (sys.argv[0], sys.argv[0]))
	sys.exit(1)

PATH = os.path.dirname(os.path.abspath(__file__))
HOME = os.path.expanduser('~')

''' Create a file to start rsf.py '''
with open(PATH+'/rsfconsole', 'w+') as f:
	f.write('#!/bin/bash\n%s/rsf.py' % PATH)
	f.close()
	os.system('/bin/chmod +x %s/rsfconsole' % PATH)

''' Write to .bashrc '''
with open(HOME + '/.bashrc', 'r+') as f:
	a = 'export PATH=$PATH:%s' % PATH
	if a not in f.read():
		f.write('\n%s\n' % a)
	f.close()

os.system('export PATH=$PATH:$(pwd)')

if platform.system().lower() == 'darwin':
	os.system('pip install -r %s/requirements.txt' % PATH)
else:
	os.system('pip install requests paramiko beautifulsoup4')
