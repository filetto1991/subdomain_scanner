# 🔍 Subdomain Scanner

A fast, concurrent, wildcard-aware subdomain enumeration tool written in pure Python.

## ✨ Features

* **Wildcard Detection** – automatically identifies wildcard DNS entries to reduce false positives.
* **Multi-record Support** – resolve A, AAAA, CNAME, MX, TXT, NS, etc.
* **Custom DNS Resolvers** – optionally use your own list of upstream DNS servers.
* **Threaded & Resilient** – configurable thread count and retry logic.
* **Progress Bar** – live feedback via `tqdm`.
* **JSON & CLI Output** – human-readable console results plus optional machine-friendly JSON export.

## ⚙️ Installation

# Clone or download the files
git clone https://github.com/filetto1991/subdomain-scanner.git
cd subdomain-scanner

# Install dependencies
pip install -r requirements.txt

## requirements.txt contains:

dnspython>=2.3.0
tqdm>=4.65.0

# Quick Start

python subdomain_scanner.py example.com -w subdomains.txt -t 50

Save results to JSON:

python subdomain_scanner.py example.com -o results.json

# Advanced Usage

| Flag                | Description                                    | Default          |
| ------------------- | ---------------------------------------------- | ---------------- |
| `-w`, `--wordlist`  | Path to subdomain wordlist                     | `subdomains.txt` |
| `-r`, `--resolvers` | File with custom DNS servers (one IP per line) | system resolver  |
| `-t`, `--threads`   | Number of concurrent threads                   | `10`             |
| `--timeout`         | Seconds to wait per DNS query                  | `2`              |
| `--tries`           | Retries per query                              | `3`              |
| `--types`           | Comma-separated DNS record types               | `A`              |
| `-o`, `--output`    | Save JSON results to file                      | *(none)*         |


## Example – enumerate A, AAAA and CNAME using 100 threads:

python subdomain_scanner.py example.com \
  -w subdomains.txt \
  -r resolvers.txt \
  -t 100 \
  --types A,AAAA,CNAME \
  -o out.json
