"""Metadata paket minimal OSINT Port Scanner.

Aplikasi tetap dijalankan dengan `python main.py` dari root proyek;
setup.py hanya memungkinkan instalasi dependensi via `pip install .`.
"""

from setuptools import find_packages, setup

setup(
    name="osint-port-scanner",
    version="0.3.0",
    description=(
        "Educational tool for domain/DNS/WHOIS information gathering and "
        "TCP port checking - for use only on systems you own or are "
        "authorized to test."
    ),
    python_requires=">=3.9",
    install_requires=["dnspython>=2.6,<3"],
    packages=find_packages(exclude=("tests", "tests.*")),
)
