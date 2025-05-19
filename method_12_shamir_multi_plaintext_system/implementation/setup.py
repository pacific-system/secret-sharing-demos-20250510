#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages

setup(
    name="shamir_multi_crypt",
    version="0.1.0",
    description="シャミア秘密分散法による複数平文復号システム",
    author="Shamir Multi-Crypt Team",
    packages=find_packages(),
    python_requires=">=3.7",
    install_requires=[
        "argon2-cffi>=21.1.0",
    ],
    entry_points={
        "console_scripts": [
            "shamir-multi-crypt=shamir_multi_crypt.cli.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
    ],
)
