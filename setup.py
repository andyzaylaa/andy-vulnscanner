"""Setup script for Andy VulnScanner."""

from setuptools import find_packages, setup

setup(
    name="andy-vulnscanner",
    version="1.0.0",
    author="Andy",
    description="A Python-based vulnerability scanner with GUI for Kali Linux",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/andyzaylaa/andy-vulnscanner",
    packages=find_packages(),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "andy-vulnscanner=vulnscanner.main:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Topic :: Security",
        "Environment :: X11 Applications",
    ],
)
