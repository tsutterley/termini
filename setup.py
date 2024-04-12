import os
from setuptools import setup, find_packages

# package description and keywords
description = 'Interactive visualization tool for the NASA MEaSUREs Terminus products'
keywords = 'glaciers, ice fronts, termini, ipython, jupyter, graphics'
# get long_description from README.rst
with open('README.rst', mode='r', encoding='utf8') as fh:
    long_description = fh.read()
long_description_content_type = "text/x-rst"

# install requirements and dependencies
on_rtd = os.environ.get('READTHEDOCS') == 'True'
if on_rtd:
    install_requires = []
else:
    # get install requirements
    with open('requirements.txt', mode='r', encoding='utf8') as fh:
        install_requires = [line.split().pop(0) for line in fh.read().splitlines()]

# get version
with open('version.txt', encoding='utf8') as fh:
    version = fh.read()

setup(
    name='termini',
    version=version,
    description=description,
    long_description=long_description,
    long_description_content_type=long_description_content_type,
    url='https://github.com/tsutterley/termini',
    author='Tyler Sutterley',
    author_email='tsutterl@uw.edu',
    license='MIT',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Science/Research',
        'Topic :: Scientific/Engineering :: Physics',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
    ],
    keywords=keywords,
    packages=find_packages(),
    install_requires=install_requires,
    include_package_data=True,
)
