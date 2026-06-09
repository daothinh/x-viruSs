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
Accepts a directory, a single binary file, or a text/CSV hash-list file.

The upgraded `-x` pipeline is designed for very large inputs. It streams the source data, splits records into shard batches, runs multiple concurrent query workers, and merges shard outputs into one final CSV report.

If `data/report_query.csv` already exists, the pipeline now uses it automatically as a local cache. Known hashes are not queried again; their saved ratio is reused and the report stays cumulative.

```bash
# Check a single file
x-virus.py -x path/to/suspicious/file.exe

# Check all files in a directory
x-virus.py -x path/to/suspicious/directory/

# Query a large CSV or TXT hash list with tuned concurrency
x-virus.py -x path/to/hash-list.csv --workers 12 --shards 96 --batch-size 100

# Write the merged report and shard work files to custom paths
x-virus.py -x path/to/hash-list.csv --report-file data/report_query.csv --work-dir data/vt_query_runs
```

Large-scale `-x` notes:
- `--batch-size` controls how many unique hashes are sent per VirusTotal request. The safe max is `100`.
- `--workers` controls concurrent shard workers.
- `--shards` controls how many intermediate shard files are created before query workers start.
- Each shard writes its own partial report, then the tool merges everything into one final CSV with columns `ratio,hash,path/to/file`.
- Existing hashes in `data/report_query.csv` are skipped automatically on rerun.
- For multi-million hash lists, prefer a hash-list file input over individual file arguments.

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
