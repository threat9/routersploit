import importlib.resources as res

filenames = ['defaults.txt', 'passwords.txt', 'usernames.txt', 'snmp.txt']
pkg_files = res.files(__name__)

paths = [f"file://{pkg_files.joinpath(n).resolve()}" for n in filenames]

defaults, passwords, usernames, snmp = paths
