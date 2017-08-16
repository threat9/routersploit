from setuptools import setup

setup(
    name='routersploit',
    version='2.2.1',
    author='Reverse Shell Security',
    packages=['routersploit','routersploit.modules','routersploit.templates','routersploit.test','routersploit.wordlists',],
    scripts=['rsf.py',],
    license='BSD-3-clause',
    long_description=open('README.md').read(),
    install_requires=['requests>=2.9.1',
                      'paramiko>=1.16.0',
                      'beautifulsoup4>=4.4.1',
                      'pysnmp>=4.3.2',
                      'gnureadline>=6.3.3',],
)
