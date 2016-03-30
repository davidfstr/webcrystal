from setuptools import setup
import os
import sys

def is_older_than(file1, file2):
    if not os.path.exists(file1) or not os.path.exists(file2):
        return False
    return os.path.getmtime(file1) < os.path.getmtime(file2)

# Generate README.rst if missing or out of date
if not os.path.exists('README.rst') or is_older_than('README.rst', 'README.md'):
    os.system('pandoc --from=markdown --to=rst --output=README.rst README.md')
with open('README.rst') as file:
    long_description = file.read()

setup(
    # Identity
    name='webcrystal',
    version='1.0',
    
    # Contents
    py_modules=['webcrystal'],
    scripts=['webcrystal.py'],
    
    # Metadata
    author='David Foster',
    author_email='david@dafoster.net',
    url='http://dafoster.net/projects/webcrystal/',
    description='A website archival tool and format.',
    long_description=long_description,
    license='MIT',
    # see: https://pypi.python.org/pypi?%3Aaction=list_classifiers
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3.4',
        'Topic :: Database',
        'Topic :: Internet :: Proxy Servers',
        'Topic :: Internet :: WWW/HTTP',
        'Topic :: Internet :: WWW/HTTP :: HTTP Servers',
        'Topic :: System :: Archiving',
        'Topic :: System :: Archiving :: Backup',
        'Topic :: System :: Archiving :: Mirroring',
    ],
    
    # Dependencies
    install_requires=[
        'urllib3'  # TODO: Include lower bound
    ]
)