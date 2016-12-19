from setuptools import Extension, setup, find_packages

import sys
import os.path
sys.path.insert(0, os.path.abspath('.'))

from mmcef import __version__

with open('requirements.txt') as f:
    _requirements = f.read().splitlines()

setup(
    name='minemeld-cef',
    version=__version__,
    author='Palo Alto Networks',
    author_email='techbizdev@paloaltonetworks.com',
    description='MineMeld output node for CEF',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 2.7',
        'Topic :: Security',
        'Topic :: Internet'
    ],
    packages=find_packages(),
    provides=find_packages(),
    install_requires=_requirements,
    package_data = {
        '': ['prototypes/*.yml', 'templates/*.yml']
    },
    entry_points={
        'minemeld_nodes': [
            'cef.Output = mmcef.node:Output'
        ],
        'minemeld_prototypes': [
            'cef.prototypes = mmcef:prototypes'
        ]
    }
)
