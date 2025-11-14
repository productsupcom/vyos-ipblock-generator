#!/usr/bin/python3
"""
VyOS IP Abuse Reporter

This module monitors VyOS firewall logs and reports blocked IP addresses to AbuseIPDB.
Automatically detects port scans and brute-force attempts from firewall rule logs.
"""

import argparse
import ipaddress
import json
import logging
import os
import re
import subprocess  # nosec B404 - subprocess usage is intentional and controlled
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Set, Dict, Tuple
import requests


class AbuseReporterConfig:
    """Configuration constants for the abuse reporter."""

    # API endpoints
    ABUSEIPDB_REPORT_URL = "https://api.abuseipdb.com/api/v2/report"

    # File paths
    ABUSEIPDB_KEY_PATH = Path("/config/scripts/abuseipdb.key")
    WHITELIST_PATH = Path("/config/scripts/whitelist.txt")
    REPORTED_IPS_CACHE = Path("/config/scripts/reported_ips.json")
    LOG_FILE = "abuse_reporter.log"

    # Timeouts and limits
    REQUEST_TIMEOUT = 30
    API_RATE_LIMIT_DELAY = 1  # seconds between API calls

    # Reporting settings
    DEFAULT_TIME_WINDOW_MINUTES = 5
    DEFAULT_RULE_NUMBERS = [999]
    ABUSE_CATEGORIES = "14.18"  # Port scan and Brute-Force
    ABUSE_COMMENT = "Port scan or Brute-Force detected."

    # Journalctl settings
    JOURNALCTL_TIMEOUT = 30


class AbuseReporterError(Exception):
    """Base exception for abuse reporting errors."""

    pass


class APIReportError(AbuseReporterError):
    """Exception raised when API report operations fail."""

    pass


class LogParseError(AbuseReporterError):
    """Exception raised when log parsing fails."""

    pass


class AbuseReporter:
    """Main class for monitoring logs and reporting abuse."""

    def __init__(
        self,
        dry_run: bool = False,
        verbose: bool = False,
        time_window_minutes: Optional[int] = None,
        rule_numbers: Optional[List[int]] = None,
        whitelist_file: Optional[str] = None,
    ):
        """
        Initialize the abuse reporter.

        Args:
            dry_run: If True, only show what would be done without reporting
            verbose: If True, enable debug logging
            time_window_minutes: Minutes of logs to check (default: 60)
            rule_numbers: Firewall rule numbers to monitor (default: [999])
            whitelist_file: Optional path to custom whitelist file
        """
        self.dry_run = dry_run
        self.config = AbuseReporterConfig()
        self._setup_logging(verbose)
        self.session = self._create_session()
        self.whitelist_file = whitelist_file

        # Time window for log checking
        self.time_window_minutes = (
            time_window_minutes or self.config.DEFAULT_TIME_WINDOW_MINUTES
        )

        # Rule numbers to monitor
        self.rule_numbers = rule_numbers or self.config.DEFAULT_RULE_NUMBERS

        # Load whitelist
        self.whitelist_ipv4: List[ipaddress.IPv4Network] = []
        self.whitelist_ipv6: List[ipaddress.IPv6Network] = []
        whitelist_result = self._load_whitelist(whitelist_file)
        self.whitelist_ipv4 = whitelist_result[0]
        self.whitelist_ipv6 = whitelist_result[1]

        # Reported IPs cache
        self.reported_cache: Dict[str, str] = self._load_reported_cache()

    def _setup_logging(self, verbose: bool) -> None:
        """Configure logging with appropriate level and handlers."""
        level = logging.DEBUG if verbose else logging.INFO

        logging.basicConfig(
            level=level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.config.LOG_FILE),
            ],
        )
        self.logger = logging.getLogger(__name__)

        if self.dry_run:
            self.logger.info("=== DRY RUN MODE - No reports will be sent ===")

    def _create_session(self) -> requests.Session:
        """Create a configured requests session."""
        session = requests.Session()
        session.headers.update({"User-Agent": "VyOS-Abuse-Reporter/1.0"})
        return session

    def _get_abuseipdb_key(self) -> Optional[str]:
        """Get AbuseIPDB API key from environment or file."""
        # Try environment variable first
        api_key = os.getenv("ABUSEIPDB_API_KEY")
        if api_key:
            api_key = api_key.strip()
            self.logger.debug(f"Using API key from environment variable (length: {len(api_key)})")
            return api_key

        # Try key file
        try:
            with open(self.config.ABUSEIPDB_KEY_PATH, "r") as f:
                first_line = f.readline().strip()
                if first_line:
                    self.logger.debug(f"Using API key from file {self.config.ABUSEIPDB_KEY_PATH} (length: {len(first_line)})")
                    return first_line
                else:
                    self.logger.error(f"API key file {self.config.ABUSEIPDB_KEY_PATH} is empty")
                    return None
        except (FileNotFoundError, PermissionError, OSError) as e:
            self.logger.error(f"Could not read API key file {self.config.ABUSEIPDB_KEY_PATH}: {e}")
            return None

    def _load_whitelist(
        self, whitelist_file: Optional[str] = None
    ) -> Tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
        """
        Load whitelist from configuration file.

        Returns:
            Tuple of (ipv4_networks, ipv6_networks)
        """
        empty_ipv4: List[ipaddress.IPv4Network] = []
        empty_ipv6: List[ipaddress.IPv6Network] = []

        whitelist_path = (
            Path(whitelist_file) if whitelist_file else self.config.WHITELIST_PATH
        )

        if not whitelist_path.exists():
            self.logger.info(f"No whitelist file found at {whitelist_path}")
            return empty_ipv4, empty_ipv6

        try:
            self.logger.info(f"Loading whitelist from {whitelist_path}")
            content = whitelist_path.read_text().strip()

            if not content:
                self.logger.info("Whitelist file is empty")
                return empty_ipv4, empty_ipv6

            ipv4_entries, ipv6_entries = self._filter_lines(content)
            ipv4_networks: List[ipaddress.IPv4Network] = self._convert_to_cidr_v4(
                ipv4_entries
            )
            ipv6_networks: List[ipaddress.IPv6Network] = self._convert_to_cidr_v6(
                ipv6_entries
            )

            self.logger.info(
                f"Loaded {len(ipv4_networks)} IPv4 and {len(ipv6_networks)} IPv6 whitelisted networks"
            )
            return ipv4_networks, ipv6_networks

        except (OSError, PermissionError) as e:
            self.logger.warning(f"Could not read whitelist file {whitelist_path}: {e}")
            return empty_ipv4, empty_ipv6
        except Exception as e:
            self.logger.error(f"Error processing whitelist file {whitelist_path}: {e}")
            return empty_ipv4, empty_ipv6

    def _filter_lines(self, data: str) -> Tuple[List[str], List[str]]:
        """
        Filter and validate IP addresses and CIDR blocks from text data.

        Args:
            data: Raw text data containing IP addresses/CIDR blocks

        Returns:
            Tuple of (ipv4_list, ipv6_list) containing valid addresses
        """
        if not data:
            self.logger.warning("No data to filter")
            return [], []

        ipv4_lines = []
        ipv6_lines = []
        invalid_count = 0

        for line_num, line in enumerate(data.splitlines(), 1):
            line = line.strip()

            # Skip comments and empty lines
            if re.match(r"^(#|;|$)", line):
                continue

            is_valid, ip_version = self._is_valid_ip_or_cidr(line)
            if is_valid:
                if ip_version == "ipv4":
                    ipv4_lines.append(line)
                elif ip_version == "ipv6":
                    ipv6_lines.append(line)
            else:
                invalid_count += 1
                self.logger.debug(f"Line {line_num}: Invalid IP/CIDR ignored: {line}")

        if invalid_count > 0:
            self.logger.debug(f"Filtered out {invalid_count} invalid entries")

        return ipv4_lines, ipv6_lines

    def _is_valid_ip_or_cidr(self, line: str) -> Tuple[bool, str]:
        """
        Validate if a line contains a valid IP address or CIDR block.

        Returns:
            Tuple of (is_valid, ip_version) where ip_version is 'ipv4' or 'ipv6'
        """
        try:
            if "/" in line:
                # For CIDR blocks, use strict=True to validate prefix lengths
                try:
                    ipaddress.IPv4Network(line, strict=True)
                    return True, "ipv4"
                except ValueError:
                    try:
                        ipaddress.IPv6Network(line, strict=True)
                        return True, "ipv6"
                    except ValueError:
                        return False, ""
            else:
                # For IP addresses, validate them directly
                try:
                    ipaddress.IPv4Address(line)
                    return True, "ipv4"
                except ValueError:
                    try:
                        ipaddress.IPv6Address(line)
                        return True, "ipv6"
                    except ValueError:
                        return False, ""
        except ValueError:
            return False, ""

    def _convert_to_cidr_v4(self, ip_list: List[str]) -> List[ipaddress.IPv4Network]:
        """Convert IPv4 addresses and CIDR blocks to IPv4Network objects."""
        cidr_list: List[ipaddress.IPv4Network] = []
        for ip in ip_list:
            try:
                if "/" in ip:
                    network = ipaddress.IPv4Network(ip, strict=False)
                else:
                    network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                cidr_list.append(network)
            except ValueError:
                self.logger.debug(f"Error converting IPv4 to CIDR: {ip}")
        return cidr_list

    def _convert_to_cidr_v6(self, ip_list: List[str]) -> List[ipaddress.IPv6Network]:
        """Convert IPv6 addresses and CIDR blocks to IPv6Network objects."""
        cidr_list: List[ipaddress.IPv6Network] = []
        for ip in ip_list:
            try:
                if "/" in ip:
                    network = ipaddress.IPv6Network(ip, strict=False)
                else:
                    network = ipaddress.IPv6Network(f"{ip}/128", strict=False)
                cidr_list.append(network)
            except ValueError:
                self.logger.debug(f"Error converting IPv6 to CIDR: {ip}")
        return cidr_list

    def _load_reported_cache(self) -> Dict[str, str]:
        """Load the cache of previously reported IPs."""
        if not self.config.REPORTED_IPS_CACHE.exists():
            self.logger.debug("No reported IPs cache found, starting fresh")
            return {}

        try:
            with open(self.config.REPORTED_IPS_CACHE, "r") as f:
                cache = json.load(f)
                self.logger.info(f"Loaded cache with {len(cache)} previously reported IPs")
                return cache
        except (json.JSONDecodeError, OSError) as e:
            self.logger.warning(f"Could not load reported IPs cache: {e}")
            return {}

    def _save_reported_cache(self) -> None:
        """Save the reported IPs cache."""
        try:
            with open(self.config.REPORTED_IPS_CACHE, "w") as f:
                json.dump(self.reported_cache, f, indent=2)
            self.logger.debug(f"Saved cache with {len(self.reported_cache)} reported IPs")
        except OSError as e:
            self.logger.error(f"Could not save reported IPs cache: {e}")

    def _is_ip_whitelisted(self, ip_str: str) -> bool:
        """Check if an IP address is in the whitelist."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if isinstance(ip, ipaddress.IPv4Address):
                return any(ip in network for network in self.whitelist_ipv4)
            elif isinstance(ip, ipaddress.IPv6Address):
                return any(ip in network for network in self.whitelist_ipv6)
        except ValueError:
            pass
        return False

    def _parse_journalctl_logs(self) -> List[Tuple[str, str, str, str]]:
        """
        Parse journalctl logs for blocked traffic.

        Returns:
            List of (ip, timestamp, src_port, dst_port) tuples
        """
        self.logger.info(f"Fetching journalctl logs from last {self.time_window_minutes} minutes")

        # Calculate since time
        since_time = datetime.now() - timedelta(minutes=self.time_window_minutes)
        since_str = since_time.strftime("%Y-%m-%d %H:%M:%S")

        # Build journalctl command
        cmd = [
            "journalctl",
            "--since", since_str,
            "--no-pager",
            "--output", "json",
        ]

        try:
            self.logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.JOURNALCTL_TIMEOUT,
            )

            if result.returncode != 0:
                error_msg = f"journalctl failed: {result.stderr}"
                self.logger.error(error_msg)
                raise LogParseError(error_msg)

            return self._parse_log_lines(result.stdout)

        except subprocess.TimeoutExpired:
            error_msg = "Timeout while fetching journalctl logs"
            self.logger.error(error_msg)
            raise LogParseError(error_msg) from None
        except subprocess.CalledProcessError as e:
            error_msg = f"Error running journalctl: {e.stderr}"
            self.logger.error(error_msg)
            raise LogParseError(error_msg) from e

    def _parse_log_lines(self, log_output: str) -> List[Tuple[str, str, str, str]]:
        """
        Parse log lines to extract blocked IPs, timestamps, and ports.

        Args:
            log_output: Raw journalctl json output

        Returns:
            List of (ip, iso_timestamp, src_port, dst_port) tuples
        """
        blocked_entries = []

        # Pattern to match firewall drop logs in the MESSAGE field
        # Example: [ipv4-FWD-filter-999-D]IN=bond0.2003 OUT=... SRC=213.138.44.126 SPT=12345 DPT=80 ...
        pattern = re.compile(
            r'\[ipv[46]-FWD-filter-(\d+)\-D\].*?SRC=([0-9a-f:.]+).*?SPT=(\d+).*?DPT=(\d+)',
            re.IGNORECASE
        )

        for line in log_output.splitlines():
            try:
                entry = json.loads(line)
                message = entry.get("MESSAGE", "")
                realtime = entry.get("__REALTIME_TIMESTAMP")
                if not realtime:
                    continue
                # Convert microseconds to datetime
                dt = datetime.fromtimestamp(int(realtime) / 1_000_000, tz=timezone.utc)
                iso_timestamp = dt.isoformat()

                match = pattern.search(message)
                if match:
                    groups = match.groups()
                    self.logger.debug(f"Regex groups: {groups}")
                    rule_num, src_ip, src_port, dst_port = groups
                    rule_num_int = int(rule_num)

                    if rule_num_int in self.rule_numbers:
                        # Default ports to empty if not found
                        src_port = src_port or ""
                        dst_port = dst_port or ""
                        self.logger.debug(f"Parsed log entry: IP={src_ip}, TS={iso_timestamp}, SPT={src_port}, DPT={dst_port}")
                        blocked_entries.append((src_ip, iso_timestamp, src_port, dst_port))
            except (json.JSONDecodeError, ValueError, KeyError):
                continue

        self.logger.info(f"Found {len(blocked_entries)} blocked traffic entries")
        return blocked_entries

    def _report_ip_to_abuseipdb(self, ip: str, timestamp: str, src_port: str = "", dst_port: str = "") -> bool:
        """
        Report a single IP to AbuseIPDB with retry on rate limit.

        Args:
            ip: IP address to report
            timestamp: ISO 8601 timestamp of the incident
            src_port: Source port (optional)
            dst_port: Destination port (optional)

        Returns:
            True if report was successful
        """
        api_key = self._get_abuseipdb_key()
        if not api_key:
            self.logger.error("No AbuseIPDB API key available")
            return False

        # Customize comment with port information
        comment = self.config.ABUSE_COMMENT
        if src_port or dst_port:
            port_info = []
            if src_port:
                port_info.append(f"src_port={src_port}")
            if dst_port:
                port_info.append(f"dst_port={dst_port}")
            comment += f" ({', '.join(port_info)})"

        if self.dry_run:
            self.logger.info(f"DRY RUN: Would report IP {ip} at {timestamp} with comment: {comment}")
            return True

        max_retries = 3
        backoff_seconds = 60  # Start with 1 minute

        for attempt in range(max_retries + 1):
            try:
                headers = {
                    "Key": api_key,
                    "Accept": "application/json",
                }

                data = {
                    "ip": ip,
                    "categories": [14, 18],  # Send as array instead of string
                    "comment": comment,
                    "timestamp": timestamp,
                }

                # self.logger.debug(f"Reporting IP {ip} to AbuseIPDB (attempt {attempt + 1}) with comment: {comment}")
                response = self.session.post(
                    self.config.ABUSEIPDB_REPORT_URL,
                    headers=headers,
                    data=data,
                    timeout=self.config.REQUEST_TIMEOUT,
                )

                response.raise_for_status()
                result = response.json()

                if result.get("data", {}).get("abuseConfidenceScore", 0) > 0:
                    self.logger.info(f"Successfully reported IP {ip} (confidence: {result['data']['abuseConfidenceScore']})")
                    return True
                else:
                    self.logger.warning(f"IP {ip} report accepted but confidence score is 0")
                    return True

            except requests.HTTPError as e:
                status_code = response.status_code
                try:
                    error_details = response.json()
                    error_msg = error_details.get('detail', str(error_details))
                except json.JSONDecodeError:
                    error_msg = response.text

                if status_code == 429 and attempt < max_retries:
                    self.logger.warning(f"Rate limit hit for IP {ip} (attempt {attempt + 1}): {error_msg}. Retrying in {backoff_seconds} seconds.")
                    time.sleep(backoff_seconds)
                    backoff_seconds *= 2  # Exponential backoff
                    continue
                else:
                    self.logger.error(f"HTTP {status_code} for IP {ip}: {error_msg}")
                    return False
            except requests.RequestException as e:
                self.logger.error(f"Failed to report IP {ip}: {e}")
                return False
            except json.JSONDecodeError as e:
                self.logger.error(f"Invalid JSON response for IP {ip}: {e}")
                return False

        self.logger.error(f"Failed to report IP {ip} after {max_retries + 1} attempts")
        return False

    def run(self) -> None:
        """Main execution method."""
        self.logger.info("=== Starting VyOS Abuse Reporting ===")

        try:
            # Get API key
            api_key = self._get_abuseipdb_key()
            if not api_key:
                raise AbuseReporterError("AbuseIPDB API key not found. Set ABUSEIPDB_API_KEY environment variable or create /config/scripts/abuseipdb.key")

            # Parse logs
            blocked_entries = self._parse_journalctl_logs()

            if not blocked_entries:
                self.logger.info("No blocked traffic found in the specified time window")
                return

            # Deduplicate and filter
            unique_entries = {}
            for ip, timestamp, src_port, dst_port in blocked_entries:
                if ip not in unique_entries:
                    unique_entries[ip] = (timestamp, src_port, dst_port)
                else:
                    # Keep the most recent timestamp
                    if timestamp > unique_entries[ip][0]:
                        unique_entries[ip] = (timestamp, src_port, dst_port)

            # Filter whitelisted IPs
            filtered_entries = {}
            for ip, (timestamp, src_port, dst_port) in unique_entries.items():
                if self._is_ip_whitelisted(ip):
                    self.logger.debug(f"Skipping whitelisted IP: {ip}")
                    continue
                filtered_entries[ip] = (timestamp, src_port, dst_port)

            # Filter already reported IPs (AbuseIPDB allows reporting same IP only once every 15 minutes)
            new_entries = {}
            current_dt = datetime.now(timezone.utc)
            for ip, (timestamp, src_port, dst_port) in filtered_entries.items():
                if ip not in self.reported_cache:
                    new_entries[ip] = (timestamp, src_port, dst_port)
                else:
                    cached_timestamp_str = self.reported_cache[ip]
                    try:
                        # Parse cached timestamp, assuming it's ISO format with Z or +00:00
                        cached_dt = datetime.fromisoformat(cached_timestamp_str.replace('Z', '+00:00')).replace(tzinfo=timezone.utc)
                        time_diff = current_dt - cached_dt
                        if time_diff < timedelta(minutes=15):
                            self.logger.debug(f"IP {ip} reported recently ({int(time_diff.total_seconds() // 60)} minutes ago), skipping")
                            continue
                        else:
                            self.logger.debug(f"IP {ip} last reported {time_diff}, re-reporting")
                            new_entries[ip] = (timestamp, src_port, dst_port)
                    except ValueError:
                        self.logger.warning(f"Invalid cached timestamp for IP {ip}: {cached_timestamp_str}, re-reporting")
                        new_entries[ip] = (timestamp, src_port, dst_port)

            if not new_entries:
                self.logger.info("No new IPs to report")
                return

            self.logger.info(f"Reporting {len(new_entries)} new blocked IPs to AbuseIPDB")

            # Report IPs with rate limiting
            reported_count = 0
            for ip, (timestamp, src_port, dst_port) in new_entries.items():
                if self._report_ip_to_abuseipdb(ip, timestamp, src_port, dst_port):
                    # Add to cache
                    self.reported_cache[ip] = timestamp
                    reported_count += 1
                    # Save cache immediately after successful report
                    if not self.dry_run:
                        self._save_reported_cache()

                # Rate limiting
                if not self.dry_run:
                    time.sleep(self.config.API_RATE_LIMIT_DELAY)

            self.logger.info(f"Successfully reported {reported_count} IPs")

        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            raise
        finally:
            self.session.close()

        self.logger.info("=== Abuse reporting completed successfully ===")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Monitor VyOS firewall logs and report blocked IPs to AbuseIPDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
   %(prog)s                          # Report blocked IPs from last 5 minutes
   %(prog)s --dry-run                # Show what would be reported
   %(prog)s --verbose                # Enable debug logging
   %(prog)s --time-window 30          # Check last 30 minutes
   %(prog)s --rules 999 1000          # Monitor rules 999 and 1000
   %(prog)s --whitelist /path/to/whitelist.txt  # Use custom whitelist
        """,
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be reported without sending reports",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose (debug) logging"
    )
    parser.add_argument(
        "--time-window",
        type=int,
        default=5,
        help="Minutes of logs to check (default: 5)",
    )
    parser.add_argument(
        "--rules",
        type=int,
        nargs="+",
        default=[999],
        help="Firewall rule numbers to monitor (default: 999)",
    )
    parser.add_argument(
        "--whitelist",
        type=str,
        help="Path to whitelist file (default: /config/scripts/whitelist.txt)",
    )

    args = parser.parse_args()

    try:
        reporter = AbuseReporter(
            dry_run=args.dry_run,
            verbose=args.verbose,
            time_window_minutes=args.time_window,
            rule_numbers=args.rules,
            whitelist_file=args.whitelist,
        )
        reporter.run()
        return 0
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Interrupted by user")
        return 130
    except Exception as e:
        logging.getLogger(__name__).error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())