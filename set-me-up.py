# -*- coding: utf-8 -*-
import re
import distutils.sysconfig as sysconfig
import os

__doc__ = '''set-me-up.

Usage:
    set-me-up <projectdir>
'''
SETUP_PY_TEMPLATE = """# -*- coding: utf-8 -*-
from setuptools import setup, find_packages

setup(
    name='%(name)s',
    version=%(version)s,
    packages=find_packages(),
    include_package_data=%(include_package_data)s,
    install_requires=[%(install_requires)s],
)
"""

STDLIB_MODULES = set()
stdlibpath = sysconfig.get_python_lib(standard_lib=True)
for top, dirs, files in os.walk(stdlibpath):
    for nm in files:
        if nm != '__init__.py' and nm[-3:] == '.py':
            STDLIB_MODULES.add(os.path.join(top, nm)[len(stdlibpath)+1:-3].replace('\\','.').split('.')[0])

IMPORT_RES = [
    re.compile(r'^import\s+(?P<package>[\w\d_]+)'),
    re.compile(r'^from\s+(?P<package>[\w\d_]+)'),
]

VERSION_RE = re.compile(r'^__version__\s=', re.M)

def guess_dependencies_from_file(path, ignore):
    with open(path) as fobj:
        data = fobj.read()
    names = set()
    for regex in IMPORT_RES:
        names.update(regex.findall(data))
    return [name for name in names if name not in ignore]



def guess_dependencies(projectdir):
    dependencies = set()
    base_ignore = [guess_name(projectdir)]
    for root, _, filenames in os.walk(projectdir):
        for filename in filenames:
            if filename.endswith('.py'):
                path = os.path.join(root, filename)
                dependencies.update(guess_dependencies_from_file(path, base_ignore + [filename[:-3] for filename in filenames if filename.endswith('.py')]))
    return ','.join(['"%s"' % name for name in dependencies if name not in STDLIB_MODULES])


def find_package_data(projectdir):
    package_data = []
    parent = guess_name(projectdir)
    for name in ['templates', 'locale', 'static']:
        if os.path.exists(os.path.join(projectdir, name)):
            package_data.append('recursive-include %s/%s *' % (parent, name))
    return '\n'.join(package_data)


def guess_name(projectdir):
    return os.path.basename(projectdir.rstrip('/'))

def guess_version(projectdir):
    with open(os.path.join(projectdir, '__init__.py')) as fobj:
        data = fobj.read()
    if VERSION_RE.search(data):
        return '__import__("%s").__version__' % guess_name(projectdir)
    else:
        return '"1.0"'


def main(projectdir):
    if not os.path.exists(projectdir):
        print "No project not found at %s" % projectdir
        return
    package_data = find_package_data(projectdir)
    context = {
        'name': guess_name(projectdir),
        'version': guess_version(projectdir),
        'include_package_data': 'True' if package_data else 'False',
        'name': guess_name(projectdir),
        'install_requires': guess_dependencies(projectdir),
    }
    with open('setup.py', 'w') as fobj:
        fobj.write(SETUP_PY_TEMPLATE % context)
    if package_data:
        with open('MANIFEST.in', 'w') as fobj:
            fobj.write(package_data)

if __name__ == '__main__':
    import docopt
    args = docopt.docopt(__doc__)
    main(args['<projectdir>'])
