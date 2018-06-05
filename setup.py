#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Always prefer setuptools over distutils
from setuptools import setup
from os import path
from codecs import open
import blockmodelbackend

here = path.abspath(path.dirname(__file__))

name = "django-blockmodelbackend"
version = blockmodelbackend.__version__
description = "Custom model backend for blocking users and ip after several attempts to access wrongly"
url = "https://github.com/JavierGonza/django-blockmodelbackend"
author = "Javier González"
author_email = "correo@javier-gonzalez.es"
license = "MIT"
keywords = "django-blockmodelbackend"
install_requires = ["Django>=1.8,<2.0", "django-ipware==2.1.0"]
classifiers = ["Intended Audience :: Developers",
               "Programming Language :: Python :: 2",
               "Programming Language :: Python :: 2.7",
               "Programming Language :: Python :: 3",
               "Programming Language :: Python :: 3.4",
               "Programming Language :: Python :: 3.5",
               "Programming Language :: Python :: 3.6",
               "Framework :: Django",
               "Framework :: Django :: 1.8",
               "Framework :: Django :: 1.9",
               "Framework :: Django :: 1.10",
               "Framework :: Django :: 1.11",
               "Development Status :: 4 - Beta",
               "License :: OSI Approved :: MIT License",
               ]
packages = ['blockmodelbackend',]
with open(path.join(here, 'README.rst'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name=name,
    version=version,
    description=description,
    long_description=long_description,
    url=url,
    author=author,
    author_email=author_email,
    license=license,
    classifiers=classifiers,
    keywords=keywords,
    packages=packages,
    install_requires=install_requires,
)
