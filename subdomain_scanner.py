#!/usr/bin/env python3
"""
subdomain_scanner.py
A concurrent, feature-rich subdomain scanner that supports:

* DNS wildcard detection
* Multi-record-type enumeration (A, AAAA, CNAME, MX, etc.)
* Custom DNS resolvers and timeouts
* Progress bar with tqdm
* JSON & CLI output
* Full CLI argument parsing

"""

# -----------------------------------------------------------------------------
# Imports
# -----------------------------------------------------------------------------
import argparse
import json
import random
import string
import sys
from typing import List, Optional, Tuple

# DNS resolution
import dns.resolver
# Concurrency
from concurrent.futures import ThreadPoolExecutor, as_completed
# Progress bar
from tqdm import tqdm


# -----------------------------------------------------------------------------
# Core Class
# -----------------------------------------------------------------------------
class SubdomainScanner:
    """
    Handles all aspects of subdomain enumeration for a single target domain.

    Responsibilities
    ----------------
    1. Load a wordlist of potential subdomains.
    2. Configure a DNS resolver with optional custom name-servers.
    3. Detect wildcard DNS entries to reduce false positives.
    4. Spawn N threads to resolve each subdomain + record-type combination.
    5. Collect, display and optionally persist results.
    """

    def __init__(
        self,
        domain: str,
        wordlist: str,
        resolver_list: Optional[str] = None,
        record_types: List[str] = None,
        threads: int = 10,
        timeout: int = 2,
        tries: int = 3,
        output: Optional[str] = None,
    ):
        """
        Parameters
        ----------
        domain : str
            The base domain we want to scan (e.g. "example.com")
        wordlist : str
            Path to a text file containing one subdomain prefix per line.
        resolver_list : Optional[str]
            Optional path to a text file containing custom DNS resolvers
            (one IP per line).  If omitted, the system resolver is used.
        record_types : List[str]
            DNS record types to query (e.g. ["A", "AAAA", "CNAME"]).
            Defaults to ["A"].
        threads : int
            Number of concurrent threads.  Clamped to ≥1.
        timeout : int
            Seconds to wait per DNS query.
        tries : int
            Number of retries per query (multiplied by timeout).
        output : Optional[str]
            If provided, results are saved as pretty-printed JSON to this path.
        """
        # Normalize defaults
        if record_types is None:
            record_types = ["A"]

        # Store raw user parameters
        self.domain = domain.lower().strip()
        self.wordlist = self._load_wordlist(wordlist)
        self.resolver = self._setup_resolver(resolver_list, timeout, tries)
        self.record_types = [rt.upper() for rt in record_types]
        self.threads = max(1, threads)
        self.output = output

    # ------------------------------------------------------------------
    # Helper: Load a wordlist file into a deduplicated list
    # ------------------------------------------------------------------
    @staticmethod
    def _load_wordlist(path: str) -> List[str]:
        """
        Reads a newline-delimited file and returns a sorted, unique list
        of lowercase subdomain prefixes.

        Raises
        ------
        FileNotFoundError
            If the provided path does not exist.
        """
        try:
            with open(path, encoding="utf-8") as f:
                # Use a set to deduplicate
                lines = {line.strip().lower() for line in f if line.strip()}
            # Sort for reproducibility
            return sorted(lines)
        except FileNotFoundError as exc:
            raise FileNotFoundError(f"[ERROR] Wordlist file not found: {path}") from exc

    # ------------------------------------------------------------------
    # Helper: Configure the DNS resolver
    # ------------------------------------------------------------------
    @staticmethod
    def _setup_resolver(
        resolver_path: Optional[str], timeout: int, tries: int
    ) -> dns.resolver.Resolver:
        """
        Creates a dns.resolver.Resolver instance with:

        * Custom timeout / retry values
        * Optional custom upstream DNS servers
        """
        resolver = dns.resolver.Resolver()
        resolver.timeout = max(1, timeout)
        resolver.lifetime = max(1, timeout * tries)

        # If a resolver file was provided, override system DNS servers
        if resolver_path:
            try:
                with open(resolver_path, encoding="utf-8") as f:
                    resolver.nameservers = [ns.strip() for ns in f if ns.strip()]
            except FileNotFoundError as exc:
                raise FileNotFoundError(
                    f"[ERROR] Resolvers file not found: {resolver_path}"
                ) from exc
        return resolver

    # ------------------------------------------------------------------
    # Wildcard Detection
    # ------------------------------------------------------------------
    def _detect_wildcard(self) -> Optional[List[str]]:
        """
        Detects whether the target domain has a wildcard DNS entry (*.{domain}).

        Method
        ------
        1. Generate a random 12-character subdomain (highly improbable).
        2. Query for its A record.
        3. If the query resolves, the wildcard is active and we return the IPs.

        Returns
        -------
        Optional[List[str]]
            List of IP addresses if wildcard detected, otherwise None.
        """
        rand_sub = "".join(
            random.choices(string.ascii_lowercase + string.digits, k=12)
        )
        test_domain = f"{rand_sub}.{self.domain}"
        try:
            answers = self.resolver.resolve(test_domain, "A")
            # Extract IPs from the answer
            return [answer.address for answer in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            # Wildcard not detected or query failed
            return None

    # ------------------------------------------------------------------
    # Public: Main scanning entry-point
    # ------------------------------------------------------------------
    def scan(self):
        """
        Orchestrates the entire scan:

        1. Detect wildcard DNS.
        2. Dispatch threaded DNS queries for each subdomain + record-type.
        3. Collect results.
        4. Present them via CLI and/or JSON file.
        """
        wildcard_ips = self._detect_wildcard()
        if wildcard_ips:
            print(
                f"[!] Wildcard DNS detected: *.{self.domain} → {wildcard_ips}",
                file=sys.stderr,
            )

        # Container for final results
        results = []

        # Thread-pool executor for concurrent DNS queries
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Map each future to its subdomain for error reporting
            future_map = {
                executor.submit(self._scan_subdomain, sub): sub for sub in self.wordlist
            }

            # Progress bar via tqdm
            for future in tqdm(
                as_completed(future_map),
                total=len(future_map),
                desc="Scanning",
                unit="sub",
            ):
                sub = future_map[future]
                try:
                    data = future.result()
                    if data:
                        domain, records = data

                        # Mark wildcard hits for user awareness
                        if wildcard_ips and any(
                            ip in wildcard_ips
                            for ip_list in records.values()
                            for ip in ip_list
                        ):
                            domain += " (WILDCARD)"

                        results.append({"subdomain": domain, "records": records})
                except Exception as exc:
                    # Log individual subdomain failures without killing the scan
                    print(f"[ERROR] {sub}: {exc}", file=sys.stderr)

        # Display results in human-readable form
        self._present_results(results)

        # Optionally save JSON
        if self.output:
            self._save_json(results)

    # ------------------------------------------------------------------
    # Internal: Resolve a single subdomain against all requested record types
    # ------------------------------------------------------------------
    def _scan_subdomain(self, subdomain: str) -> Optional[Tuple[str, dict]]:
        """
        Queries all requested DNS record types for a single subdomain.

        Parameters
        ----------
        subdomain : str
            The subdomain prefix (e.g. "api" for "api.example.com").

        Returns
        -------
        Optional[Tuple[str, dict]]
            (full_domain, records_dict) if any records were found,
            otherwise None to indicate a non-existent subdomain.
        """
        full_domain = f"{subdomain}.{self.domain}"
        record_map = {}

        for rt in self.record_types:
            try:
                answers = self.resolver.resolve(full_domain, rt)
                record_map[rt] = [answer.address for answer in answers]
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                # Either the subdomain does not exist, or the record type
                # is not present.  We simply continue without adding it.
                continue

        # Only return a result if we found at least 1 record type
        return (full_domain, record_map) if record_map else None

    # ------------------------------------------------------------------
    # Helper: Pretty print results to stdout
    # ------------------------------------------------------------------
    @staticmethod
    def _present_results(results: List[dict]):
        """
        Prints a concise, human-readable list of discovered subdomains.

        Format
        ------
        [+] subdomain.example.com
            A    1.2.3.4
            AAAA 2001:db8::1
        """
        if not results:
            print("[INFO] No active subdomains found.")
            return

        for item in results:
            dom = item["subdomain"]
            print(f"[+] {dom}")
            for rt, ips in item["records"].items():
                for ip in ips:
                    print(f"    {rt}\t{ip}")

    # ------------------------------------------------------------------
    # Helper: Persist results as JSON
    # ------------------------------------------------------------------
    def _save_json(self, results: List[dict]):
        """
        Serializes the results list to a pretty-printed JSON file.

        Structure
        ---------
        [
          {
            "subdomain": "api.example.com",
            "records": {
              "A": ["1.2.3.4"],
              "AAAA": ["2001:db8::1"]
            }
          },
          ...
        ]
        """
        try:
            with open(self.output, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            print(f"[INFO] Results saved to {self.output}")
        except OSError as exc:
            print(f"[ERROR] Failed to write JSON file: {exc}", file=sys.stderr)


# -----------------------------------------------------------------------------
# CLI Entry-Point
# -----------------------------------------------------------------------------
def main():
    """
    Parses command-line arguments and instantiates SubdomainScanner.
    """
    parser = argparse.ArgumentParser(
        description="Concurrent, wildcard-aware subdomain scanner"
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument(
        "-w",
        "--wordlist",
        default="subdomains.txt",
        help="Path to wordlist file (default: subdomains.txt)",
    )
    parser.add_argument(
        "-r",
        "--resolvers",
        help="Path to file with custom DNS resolvers (one per line)",
    )
    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=2,
        help="Timeout per DNS query in seconds (default: 2)",
    )
    parser.add_argument(
        "--tries",
        type=int,
        default=3,
        help="Retries per DNS query (default: 3)",
    )
    parser.add_argument(
        "--types",
        default="A",
        help="Comma-separated DNS record types (default: A)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Save results to JSON file",
    )
    args = parser.parse_args()

    try:
        scanner = SubdomainScanner(
            domain=args.domain,
            wordlist=args.wordlist,
            resolver_list=args.resolvers,
            record_types=[t.strip() for t in args.types.split(",")],
            threads=args.threads,
            timeout=args.timeout,
            tries=args.tries,
            output=args.output,
        )
        scanner.scan()
    except FileNotFoundError as e:
        print(e, file=sys.stderr)
        sys.exit(1)


# -----------------------------------------------------------------------------
# Script Guard
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
