from importlib.resources import files


defaults = 'file://' + str(files(__name__).joinpath('defaults.txt'))
passwords = 'file://' + str(files(__name__).joinpath('passwords.txt'))
usernames = 'file://' + str(files(__name__).joinpath('usernames.txt'))
snmp = 'file://' + str(files(__name__).joinpath('snmp.txt'))
