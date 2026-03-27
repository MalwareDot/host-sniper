#!/usr/bin/env python3
"""
Setup script for Host Sniper
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="host-sniper",
    version="0.1.1",
    author="malwaredot",
    author_email="malwaredot@github.com",
    description="Combined security scanning and reconnaissance tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/malwaredot/host-sniper",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8+",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.28.0",
        "rich>=13.0.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "host-sniper=host_sniper.main:main",
        ],
    },
)
