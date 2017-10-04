# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name='routersploit',
    version="1.0",
    packages=find_packages(),
    include_package_data=False,
    install_requires=["binascii","pkg_resources","time","requests","pysnmp","paramiko""beautifulsoup4","requests" ],
)
