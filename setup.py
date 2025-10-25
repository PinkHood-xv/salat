#!/usr/bin/env python3
"""
SALAT v2 - SOC Analyst Log Analysis Toolkit
Setup script for package installation
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the contents of README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text()

setup(
    name="salat",
    version="2.0.0",
    author="SALAT Project Contributors",
    description="Professional SOC Analyst Log Analysis Toolkit",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/salat",  # Update with your GitHub URL
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Logging",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    python_requires=">=3.7",
    install_requires=[
        "python-dateutil>=2.8.0",
    ],
    extras_require={
        "evtx": ["python-evtx>=0.7.0"],
        "csv": ["pandas>=1.3.0"],
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.12",
            "black>=21.0",
            "flake8>=3.9",
            "mypy>=0.910",
        ],
    },
    entry_points={
        "console_scripts": [
            "salat=lib.cli:main",
        ],
    },
    scripts=["salat"],
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt"],
        "sample_logs": ["*"],
    },
    keywords="security log-analysis soc threat-detection pcap syslog evtx forensics",
    project_urls={
        "Bug Reports": "https://github.com/yourusername/salat/issues",
        "Source": "https://github.com/yourusername/salat",
        "Documentation": "https://github.com/yourusername/salat/blob/main/README.md",
    },
)
