#!/usr/bin/env python
# -*- coding: utf-8 -*-


try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup


with open('README.md') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [
    'gnureadline==6.3.3',
]

test_requirements = [
    # TODO: put package test requirements here
]

setup(
    name='routersploit',
    version='0.1.0',
    description="The Router Exploitation Framework",
    long_description=readme + '\n\n' + history,
    author="Marcin Bury",
    author_email='office@reverse-shell.com',
    url='https://github.com/lucyoa/routersploit',
    packages=[
        'routersploit',
    ],
    package_dir={'routersploit':
                 'routersploit'},
    include_package_data=True,
    install_requires=requirements,
    license="ISCL",
    zip_safe=False,
    keywords='routersploit',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: ISC License (ISCL)',
        'Natural Language :: English',
        "Programming Language :: Python :: 2",
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
    ],
    test_suite='tests',
    tests_require=test_requirements,
    entry_points={
        'console_scripts': [
            'rsf = routersploit.scripts.rsf:routersploit',
        ]
    }
)
