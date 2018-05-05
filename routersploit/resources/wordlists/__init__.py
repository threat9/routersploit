import pkg_resources


defaults = 'file://' + pkg_resources.resource_filename(__name__, 'defaults.txt')
passwords = 'file://' + pkg_resources.resource_filename(__name__, 'passwords.txt')
usernames = 'file://' + pkg_resources.resource_filename(__name__, 'usernames.txt')
snmp = 'file://' + pkg_resources.resource_filename(__name__, 'snmp.txt')
