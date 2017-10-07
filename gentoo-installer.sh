#!/bin/bash
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root / su -s " 
   exit 1
fi

######### For Routersploit RSF install for Gentoo 
### Alpha... Quality Script..   still needs work ... 
### icon and desktop thingy also needs tweaking.. 
echo "Routersploit RSF install for Gentoo, ebuild soon-ish... " 

 

add_deps() {
## add minimal depends to run RSF. # -av ask verbose... 
## will skip if already at newer sabayn may just quickly re-install bins 
echo    "Instillation of  minimal depends " 
### use Sabayon entropy else much faster on sabayon related boxes. to use binaries.
if command_exists equo ; then
    equo i dev-python/beautifulsoup dev-python/requests dev-python/pysnmp dev-python/pexpect
elif	
 
 emerge -av --buildpkg dev-python/beautifulsoup dev-python/requests dev-python/pysnmp dev-python/pexpect 
fi
 }

 
add_repo() {
read -p "would you like to Add Pentoo overlay if you haven't already... "? " -n 1 -r
echo    "Pentoo has many usefull tools wich may be usefull if rsf intergrates with MSF/Veil etc, at your option"
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do layman
	layman -S & layman -A pento
}

add_rsf() {
 echo "cloneing Routersploit" 
  cd /usr/src
    git clone https://github.com/reverse-shell/routersploit.git
   }
   
add_tdeps() {
 echo    "Next We will do build/test via docker , not required but if you want Q/A test <Y> 
 read -p "would you like to run Testdeps and make makefile/docker ... "? " -n 1 -r
echo   "your welcome to decline if you havent docker runining else wish to skip.)
echo    # (optional) move to a new line
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do test deps docker build etc # -av ask verbose... 
	if command_exists equo ; then
	equo i virtual/python-mock   dev-python/flake8  app-emulation/docker
	elif 
	emerge -av --buildpkg  virtual/python-mock   dev-python/flake8  app-emulation/docker
  cd /usr/src/routersploit
  make 
  fi
}

install_rsf() {
       mkdir -p /opt/routersploit 
	   ## make dir path
    cp    /usr/src/routersploit/rsf.py   /opt/routersploit/rsf.py
    cp -r /usr/src/routersploit/routersploit   /opt/routersploit
	## ensure py script is executable.
	chmod -x /opt/routersploit/rsf.py
	# Quick lazy alias... 
    ln -s /opt/routersploit/rsf.py  /usr/bin/rsf/  
	}
	
	install_rsficons() {
	read -p "Are you wanting desktop Icons and other lazyness.  " -n 1 -r
 echo    # (optional) move to a new line
   ### 
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # do icons
	## add crapy png icon I made , hopefully they will Improve.. them but for now 
	## hear's the easy button. --begin lazy 
	## and a Desktop Xtem launcher to fire routersploit in xterm
	
	 mkdir - p /usr/share/icons/routerspliot/  
     cp  /usr/src/routersploit/art/routersploit.png  /usr/share/icons/routerspliot/ 
     mkdir - p /usr/share/applications/routerspliot/
     cp /usr/src/routersploit/art/*.desktop  /usr/share/applications/routerspliot/  
fi
 