#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
from setuptools import setup, find_packages

setup(
    name = "SMASS",
    version = "0.0.1",
    author = "Espen Fjellvær Olsen",
    author_email = "espen@mrfjo.org",
    description = ("Tool to do static analysis and storage/cataloguing malware/artifacts."),
    license = "GPLv3",
    keywords = "static malware analysis storage",
    url = "https://github.com/espenfjo/smass",
    install_requires=[
        'configobj', 'python-magic', 'pefile', 'urllib3', 'crypto', 'numpy', 'yara_python', 'pydeep', 'pymongo', 'jsbeautifier'],
    packages=find_packages(),
    )
