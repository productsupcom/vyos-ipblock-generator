#!/usr/bin/env python3

from setuptools import setup, find_packages
import os

# Read long description safely
long_description = "VyOS IP blocklist generator from threat intelligence sources"
if os.path.exists("README.md"):
    with open("README.md", "r", encoding="utf-8") as f:
        long_description = f.read()

setup(
    name="vyos-ipblock-generator",
    version="1.0.2",
    description="VyOS IP blocklist generator from threat intelligence sources",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="VyOS IP Blocklist Generator",
    author_email="wieger.bontekoe@productsup.com",
    url="https://github.com/productsupcom/vyos-ipblock-generator",
    py_modules=["generate_blocklist"],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.25.0",
    ],
    entry_points={
        "console_scripts": [
            "vyos-ipblock=generate_blocklist:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking :: Firewalls",
        "Topic :: Security",
    ],
)
