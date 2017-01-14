from setuptools import Extension, setup, find_packages
try:
    from Cython.Build import cythonize
except ImportError:
    cythonize = lambda x: x

import sys
import os.path
import json
sys.path.insert(0, os.path.abspath('.'))

with open('requirements.txt') as f:
    _requirements = f.read().splitlines()

with open('minemeld.json') as f:
    _metadata = json.load(f)

_entry_points={}
if 'entry_points' in _metadata:
    for epgroup, epoints in _metadata['entry_points'].iteritems():
        _entry_points[epgroup] = ['{} = {}'.format(k, v) for k, v in epoints.iteritems()]

GIROLAMO = Extension(
    name='mmcef.packages.girolamo._vm',
    sources=['mmcef/packages/girolamo/_vm.pyx']
)

setup(
    name=_metadata['name'],
    version=_metadata['version'],
    author=_metadata['author'],
    author_email=_metadata['author_email'],
    description=_metadata['description'],
    classifiers=[
        'Framework :: MineMeld',
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: Internet'
    ],
    packages=find_packages(),
    provides=find_packages(),
    install_requires=_requirements,
    setup_requires=['cython'],
    ext_modules=cythonize([GIROLAMO]),
    package_data = {
        '': ['prototypes/*.yml', 'templates/*.yml']
    },
    entry_points=_entry_points
)
