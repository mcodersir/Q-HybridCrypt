"""
Setup script for Q-HybridCrypt v2.0 "PHOENIX"
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="q-hybridcrypt",
    version="2.0.0",
    author="Q-HybridCrypt Development Team",
    author_email="info@q-hybridcrypt.ir",
    description="Quantum-Resistant Hybrid Cryptographic Library - Triple-Cascade Encryption with Module-LWE KEM & Migration SDK",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mcodersir/Q-HybridCrypt",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Science/Research",
        "Topic :: Security :: Cryptography",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Operating System :: OS Independent",
        "Typing :: Typed",
    ],
    python_requires=">=3.8",
    install_requires=[
        # No mandatory dependencies - completely standalone!
        # All cryptographic primitives are implemented in pure Python.
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "black>=22.0.0",
            "mypy>=1.0.0",
        ],
        "performance": [
            "cryptography>=40.0.0",
            "argon2-cffi>=21.0.0",
        ],
        "migration": [
            "cryptography>=40.0.0",
        ],
        "all": [
            "cryptography>=40.0.0",
            "argon2-cffi>=21.0.0",
            "pytest>=7.0.0",
            "black>=22.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "qhybridcrypt-demo=examples.basic_usage:run_all_examples",
            "qhybridcrypt-test=tests.test_core:run_all_tests",
        ],
    },
    keywords="cryptography quantum-resistant post-quantum pqc hybrid aes gcm chacha20 argon2 lattice lwe kem cascade encryption security migration sdk",
    project_urls={
        "Bug Reports": "https://github.com/mcodersir/Q-HybridCrypt/issues",
        "Source": "https://github.com/mcodersir/Q-HybridCrypt",
        "Documentation": "https://github.com/mcodersir/Q-HybridCrypt/tree/main/docs",
    },
)
