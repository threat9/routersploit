#!/usr/bin/env python2.7
from setuptools import setup,find_packages

setup(name='routersploit',
      version='2.2.1',
      description='The Router Exploitation Framework',
      author='Reverse Shell Security',
      author_email='office@reverse-shell.com',
      url='https://www.reverse-shell.com/',
      download_url='https://github.com/reverse-shell/routersploit',
      license='BSD',
      packages=find_packages(),
      package_data={'routersploit' : ['wordlists/*.txt']},
      data_files=[('bin',['rsf.py'])],
      requires = [
           'requests(>=2.9.1)',
           'paramiko(>=1.16.0)',
           'beautifulsoup4(>=4.4.1)',
           'pysnmp(>=4.3.2)',
           'gnureadline(>=6.3.3)',
      ],
      classifiers = [
           'Development Status :: 4 - Beta',
           'Environment :: Console',
           'Environment :: Console :: Curses',
           'Intended Audience :: Developers',
           'Intended Audience :: Education',
           'Intended Audience :: Information Technology',
           'Intended Audience :: Science/Research',
           'Intended Audience :: System Administrators',
           'Intended Audience :: Telecommunications Industry',
           'License :: OSI Approved :: BSD License',
           'Operating System :: OS Independent',
           'Programming Language :: Python',
           'Topic :: Security',
           'Topic :: System :: Networking',
           'Topic :: Utilities'
      ]
     )
