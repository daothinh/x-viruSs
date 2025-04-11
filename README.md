# x-vriuSs

<p align="center">
  <img src="https://img.shields.io/badge/version-1.1.2-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows|Linux-lightgrey.svg" alt="Platform">
</p>

> Crank it up — dancing with the malware. ^^

## 📋 Overview

x-vriuSs allows security professionals to analyze files for malicious content, check detection ratios across various antivirus engines, and retrieve sample malware for security research purposes.

## 🚀 Installation

```bash
git clone https://github.com/yourusername/x-vriuSs.git
cd x-vriuSs
pip install -r requirements.txt
```

## 🔧 Usage

```bash
x-virus.py [options] [value]
```

x-vriuSs is a powerful tool for analyzing file systems and detecting malware using multiple security APIs.

### Available Options

| Option | Description | Example |
|--------|-------------|---------|
| `-x PATH [PATH ...]` | Check detection ratio of files or directories on VirusTotal | `x-virus.py -x suspicious.exe` |
| `-pecheck FILE` | Show file version, timestamp, and digital signature details | `x-virus.py -pecheck program.exe` |
| `-hybrid HASH [HASH ...]` | Download sample malicious files from Hybrid Analysis | `x-virus.py -hybrid 44d88612fea8a8f36de82e1278abb02f` |
| `-v, --version` | Show program's version number and exit | `x-virus.py -v` |
| `-h, --help` | Show help message and exit | `x-virus.py -h` |

### Detailed Documentation

#### VirusTotal Check (-x)
Accepts either a file path or directory path:
```bash
# Check a single file
x-virus.py -x path/to/suspicious/file.exe

# Check all files in a directory
x-virus.py -x path/to/suspicious/directory/
```

#### Hybrid Analysis (-hybrid)
Accepts one or multiple hash values, or a path to a CSV file containing hashes:
```bash
# Download a sample with a specific hash
x-virus.py -hybrid 44d88612fea8a8f36de82e1278abb02f

# Download multiple samples at once
x-virus.py -hybrid hash1 hash2 hash3

# Use a CSV file (format: hash,name)
x-virus.py -hybrid path/to/hash_list.csv
```

#### PE File Analysis (-pecheck)
Coming soon - 

#### VRShare Integration (-vrshare)
Coming soon - 