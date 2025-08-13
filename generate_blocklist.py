#!/usr/bin/python3
"""
VyOS IP Blocklist Generator

This module generates and applies IP blocklists to VyOS nftables from multiple threat intelligence sources.
Supports Emerging Threats, Binary Defense, and AbuseIPDB feeds.
"""

import argparse
import ipaddress
import logging
import os
import re
import subprocess  # nosec B404 - subprocess usage is intentional and controlled
import tempfile
import time
from pathlib import Path
from typing import List, Optional, Set, Union
import requests


class BlocklistConfig:
    """Configuration constants for the blocklist generator."""
    
    # API endpoints
    EMERGING_THREATS_URL = 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
    BINARY_DEFENSE_URL = 'https://www.binarydefense.com/banlist.txt'
    ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/blacklist'
    
    # File paths
    ABUSEIPDB_KEY_PATH = Path('/config/scripts/abuseipdb.key')
    WHITELIST_PATH = Path('/config/scripts/whitelist.txt')
    LOG_FILE = 'blocklist.log'
    
    # Timeouts and limits
    REQUEST_TIMEOUT = 30
    NFT_TIMEOUT = 30
    
    # AbuseIPDB settings
    ABUSEIPDB_CONFIDENCE_MINIMUM = 90
    
    # nftables configuration
    NFT_TABLE = 'vyos_filter'
    NFT_SET_IPV4 = 'N_threats-blocklist-ipv4'
    NFT_SET_IPV6 = 'N6_threats-blocklist-ipv6'  # Changed to match your firewall rule
    
    # Legacy set name for backward compatibility
    NFT_SET = NFT_SET_IPV4


class BlocklistGeneratorError(Exception):
    """Base exception for blocklist generation errors."""
    pass


class APIFetchError(BlocklistGeneratorError):
    """Exception raised when API fetch operations fail."""
    pass


class NFTConfigError(BlocklistGeneratorError):
    """Exception raised when nftables configuration fails."""
    pass


class BlocklistGenerator:
    """Main class for generating and applying IP blocklists."""
    
    def __init__(self, dry_run: bool = False, verbose: bool = False, whitelist_file: Optional[str] = None):
        """
        Initialize the blocklist generator.
        
        Args:
            dry_run: If True, only show what would be done without making changes
            verbose: If True, enable debug logging
            whitelist_file: Optional path to custom whitelist file
        """
        self.dry_run = dry_run
        self.config = BlocklistConfig()
        self._setup_logging(verbose)
        self.session = self._create_session()
        self.whitelist_file = whitelist_file
        self.whitelist_ipv4, self.whitelist_ipv6 = self._load_whitelist(whitelist_file)

    def _setup_logging(self, verbose: bool) -> None:
        """Configure logging with appropriate level and handlers."""
        level = logging.DEBUG if verbose else logging.INFO
        
        logging.basicConfig(
            level=level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(self.config.LOG_FILE)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        if self.dry_run:
            self.logger.info("=== DRY RUN MODE - No changes will be made ===")
    
    def _create_session(self) -> requests.Session:
        """Create a configured requests session."""
        session = requests.Session()
        session.headers.update({'User-Agent': 'VyOS-Blocklist-Generator/1.0'})
        return session
    
    def _fetch_url(self, url: str, headers: Optional[dict] = None, 
                   params: Optional[dict] = None) -> str:
        """
        Fetch content from a URL with proper error handling.
        
        Args:
            url: The URL to fetch
            headers: Optional additional headers
            params: Optional URL parameters
            
        Returns:
            The response text, or empty string on error
            
        Raises:
            APIFetchError: If the request fails after retries
        """
        if headers is None:
            headers = {}
            
        try:
            self.logger.info(f"Fetching URL: {url}")
            start_time = time.time()
            
            response = self.session.get(
                url, 
                headers=headers, 
                params=params, 
                timeout=self.config.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            
            elapsed = time.time() - start_time
            self.logger.info(
                f"Successfully fetched {url}, "
                f"response size: {len(response.text)} bytes, "
                f"elapsed: {elapsed:.2f}s"
            )
            return response.text
            
        except requests.RequestException as e:
            error_msg = f"Error fetching {url}: {e}"
            self.logger.error(error_msg)
            raise APIFetchError(error_msg) from e

    def _is_valid_ip_or_cidr(self, line: str) -> tuple[bool, str]:
        """
        Validate if a line contains a valid IP address or CIDR block.
        
        Returns:
            Tuple of (is_valid, ip_version) where ip_version is 'ipv4' or 'ipv6'
        """
        try:
            if '/' in line:
                try:
                    ipaddress.IPv4Network(line, strict=False)
                    return True, 'ipv4'
                except ValueError:
                    ipaddress.IPv6Network(line, strict=False)
                    return True, 'ipv6'
            else:
                try:
                    ipaddress.IPv4Address(line)
                    return True, 'ipv4'
                except ValueError:
                    ipaddress.IPv6Address(line)
                    return True, 'ipv6'
        except ValueError:
            return False, ''
    
    def _filter_lines(self, data: str) -> tuple[List[str], List[str]]:
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
            if re.match(r'^(#|;|$)', line):
                continue
            
            is_valid, ip_version = self._is_valid_ip_or_cidr(line)
            if is_valid:
                if ip_version == 'ipv4':
                    ipv4_lines.append(line)
                elif ip_version == 'ipv6':
                    ipv6_lines.append(line)
            else:
                invalid_count += 1
                self.logger.debug(f"Line {line_num}: Invalid IP/CIDR ignored: {line}")
        
        if invalid_count > 0:
            self.logger.debug(f"Filtered out {invalid_count} invalid entries")
        
        return ipv4_lines, ipv6_lines

    def fetch_emerging_threats(self) -> tuple[List[str], List[str]]:
        """Fetch blocklist from Emerging Threats."""
        self.logger.info("Fetching Emerging Threats blocklist")
        try:
            data = self._fetch_url(self.config.EMERGING_THREATS_URL)
            ipv4_data, ipv6_data = self._filter_lines(data)
            self.logger.info(f"Emerging Threats: {len(ipv4_data)} IPv4, {len(ipv6_data)} IPv6 valid entries found")
            return ipv4_data, ipv6_data
        except APIFetchError:
            self.logger.warning("Failed to fetch Emerging Threats data, continuing without it")
            return [], []

    def fetch_binary_defense(self) -> tuple[List[str], List[str]]:
        """Fetch blocklist from Binary Defense."""
        self.logger.info("Fetching Binary Defense blocklist")
        try:
            data = self._fetch_url(self.config.BINARY_DEFENSE_URL)
            ipv4_data, ipv6_data = self._filter_lines(data)
            self.logger.info(f"Binary Defense: {len(ipv4_data)} IPv4, {len(ipv6_data)} IPv6 valid entries found")
            return ipv4_data, ipv6_data
        except APIFetchError:
            self.logger.warning("Failed to fetch Binary Defense data, continuing without it")
            return [], []

    def fetch_abuseipdb(self) -> tuple[List[str], List[str]]:
        """Fetch blocklist from AbuseIPDB."""
        self.logger.info("Fetching AbuseIPDB blocklist")
        
        api_key = self._get_abuseipdb_key()
        if not api_key:
            self.logger.warning("ABUSEIPDB_API_KEY not available, skipping AbuseIPDB")
            return [], []
        
        headers = {
            'Key': api_key,
            'Accept': 'text/plain'
        }
        params = {
            'confidenceMinimum': self.config.ABUSEIPDB_CONFIDENCE_MINIMUM
        }
        
        try:
            data = self._fetch_url(self.config.ABUSEIPDB_URL, headers=headers, params=params)
            ipv4_data, ipv6_data = self._filter_lines(data)
            self.logger.info(f"AbuseIPDB: {len(ipv4_data)} IPv4, {len(ipv6_data)} IPv6 valid entries found")
            return ipv4_data, ipv6_data
        except APIFetchError:
            self.logger.warning("Failed to fetch AbuseIPDB data, continuing without it")
            return [], []

    def _get_abuseipdb_key(self) -> Optional[str]:
        """Get AbuseIPDB API key from environment or file."""
        # Try environment variable first
        api_key = os.getenv('ABUSEIPDB_API_KEY')
        if api_key:
            return api_key.strip()
        
        # Try key file - read only the first line to avoid issues with extra content
        try:
            with open(self.config.ABUSEIPDB_KEY_PATH, 'r') as f:
                first_line = f.readline().strip()
                if first_line:
                    return first_line
                return None
        except (FileNotFoundError, PermissionError, OSError) as e:
            self.logger.debug(f"Could not read API key file: {e}")
            return None

    def _convert_to_cidr_v4(self, ip_list: List[str]) -> List[ipaddress.IPv4Network]:
        """Convert IPv4 addresses and CIDR blocks to IPv4Network objects."""
        self.logger.info(f"Converting {len(ip_list)} IPv4 entries to CIDR format")
        cidr_list: List[ipaddress.IPv4Network] = []
        conversion_errors = 0
        
        for ip in ip_list:
            try:
                if '/' in ip:
                    network = ipaddress.IPv4Network(ip, strict=False)
                else:
                    network = ipaddress.IPv4Network(f"{ip}/32", strict=False)
                cidr_list.append(network)
            except ValueError:
                conversion_errors += 1
                self.logger.debug(f"Error converting IPv4 to CIDR: {ip}")
        
        if conversion_errors > 0:
            self.logger.warning(f"Failed to convert {conversion_errors} IPv4 entries to CIDR")
        
        self.logger.info(f"Successfully converted {len(cidr_list)} IPv4 entries to CIDR")
        return cidr_list
    
    def _convert_to_cidr_v6(self, ip_list: List[str]) -> List[ipaddress.IPv6Network]:
        """Convert IPv6 addresses and CIDR blocks to IPv6Network objects."""
        self.logger.info(f"Converting {len(ip_list)} IPv6 entries to CIDR format")
        cidr_list: List[ipaddress.IPv6Network] = []
        conversion_errors = 0
        
        for ip in ip_list:
            try:
                if '/' in ip:
                    network = ipaddress.IPv6Network(ip, strict=False)
                else:
                    network = ipaddress.IPv6Network(f"{ip}/128", strict=False)
                cidr_list.append(network)
            except ValueError:
                conversion_errors += 1
                self.logger.debug(f"Error converting IPv6 to CIDR: {ip}")
        
        if conversion_errors > 0:
            self.logger.warning(f"Failed to convert {conversion_errors} IPv6 entries to CIDR")
        
        self.logger.info(f"Successfully converted {len(cidr_list)} IPv6 entries to CIDR")
        return cidr_list

    def _deduplicate_and_filter_list_v4(self, cidr_list: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
        """Remove duplicate and redundant IPv4 CIDR blocks."""
        self.logger.info(f"Deduplicating and filtering {len(cidr_list)} IPv4 CIDR entries")
        original_count = len(cidr_list)
        
        # Sort by network address and prefix length
        cidr_list.sort(key=lambda x: (x.network_address, x.prefixlen))
        
        # Remove networks contained within larger blocks
        filtered_list: List[ipaddress.IPv4Network] = []
        for cidr in cidr_list:
            if not any(cidr.subnet_of(existing) for existing in filtered_list):
                filtered_list.append(cidr)
        
        removed_count = original_count - len(filtered_list)
        self.logger.info(f"Removed {removed_count} redundant IPv4 entries, {len(filtered_list)} unique entries remaining")
        return filtered_list
    
    def _deduplicate_and_filter_list_v6(self, cidr_list: List[ipaddress.IPv6Network]) -> List[ipaddress.IPv6Network]:
        """Remove duplicate and redundant IPv6 CIDR blocks."""
        self.logger.info(f"Deduplicating and filtering {len(cidr_list)} IPv6 CIDR entries")
        original_count = len(cidr_list)
        
        # Sort by network address and prefix length
        cidr_list.sort(key=lambda x: (x.network_address, x.prefixlen))
        
        # Remove networks contained within larger blocks
        filtered_list: List[ipaddress.IPv6Network] = []
        for cidr in cidr_list:
            if not any(cidr.subnet_of(existing) for existing in filtered_list):
                filtered_list.append(cidr)
        
        removed_count = original_count - len(filtered_list)
        self.logger.info(f"Removed {removed_count} redundant IPv6 entries, {len(filtered_list)} unique entries remaining")
        return filtered_list

    def _load_whitelist(self, whitelist_file: Optional[str] = None) -> tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
        """
        Load whitelist from configuration file.
        
        Returns:
            Tuple of (ipv4_networks, ipv6_networks)
        """
        whitelist_path = Path(whitelist_file) if whitelist_file else self.config.WHITELIST_PATH
        
        if not whitelist_path.exists():
            self.logger.info(f"No whitelist file found at {whitelist_path}")
            return [], []
        
        try:
            self.logger.info(f"Loading whitelist from {whitelist_path}")
            content = whitelist_path.read_text().strip()
            
            if not content:
                self.logger.info("Whitelist file is empty")
                return [], []
            
            ipv4_entries, ipv6_entries = self._filter_lines(content)
            ipv4_networks = self._convert_to_cidr_v4(ipv4_entries)
            ipv6_networks = self._convert_to_cidr_v6(ipv6_entries)
            
            self.logger.info(f"Loaded {len(ipv4_networks)} IPv4 and {len(ipv6_networks)} IPv6 whitelisted networks")
            for network in ipv4_networks:
                self.logger.debug(f"Whitelisted IPv4: {network}")
            for network in ipv6_networks:
                self.logger.debug(f"Whitelisted IPv6: {network}")
            
            return ipv4_networks, ipv6_networks
            
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Could not read whitelist file {whitelist_path}: {e}")
            return [], []
        except Exception as e:
            self.logger.error(f"Error processing whitelist file {whitelist_path}: {e}")
            return [], []

    def _apply_whitelist_filter_v4(self, cidr_list: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
        """Filter out whitelisted IPv4 networks from the blocklist."""
        if not self.whitelist_ipv4:
            self.logger.debug("No IPv4 whitelist configured, skipping IPv4 whitelist filtering")
            return cidr_list
        
        self.logger.info(f"Applying IPv4 whitelist filter to {len(cidr_list)} entries")
        original_count = len(cidr_list)
        
        filtered_list = []
        whitelisted_count = 0
        
        for network in cidr_list:
            if any(network.subnet_of(whitelist_net) or network.supernet_of(whitelist_net) or network.overlaps(whitelist_net) 
                   for whitelist_net in self.whitelist_ipv4):
                whitelisted_count += 1
                self.logger.debug(f"Filtered out whitelisted IPv4 network: {network}")
            else:
                filtered_list.append(network)
        
        self.logger.info(f"IPv4 whitelist filtering: removed {whitelisted_count} entries, {len(filtered_list)} entries remaining")
        return filtered_list

    def _apply_whitelist_filter_v6(self, cidr_list: List[ipaddress.IPv6Network]) -> List[ipaddress.IPv6Network]:
        """Filter out whitelisted IPv6 networks from the blocklist."""
        if not self.whitelist_ipv6:
            self.logger.debug("No IPv6 whitelist configured, skipping IPv6 whitelist filtering")
            return cidr_list
        
        self.logger.info(f"Applying IPv6 whitelist filter to {len(cidr_list)} entries")
        original_count = len(cidr_list)
        
        filtered_list = []
        whitelisted_count = 0
        
        for network in cidr_list:
            if any(network.subnet_of(whitelist_net) or network.supernet_of(whitelist_net) or network.overlaps(whitelist_net) 
                   for whitelist_net in self.whitelist_ipv6):
                whitelisted_count += 1
                self.logger.debug(f"Filtered out whitelisted IPv6 network: {network}")
            else:
                filtered_list.append(network)
        
        self.logger.info(f"IPv6 whitelist filtering: removed {whitelisted_count} entries, {len(filtered_list)} entries remaining")
        return filtered_list

    def generate_blocklist(self) -> tuple[List[ipaddress.IPv4Network], List[ipaddress.IPv6Network]]:
        """
        Generate the complete blocklist from all sources.
        
        Returns:
            Tuple of (ipv4_networks, ipv6_networks)
        """
        self.logger.info("Starting blocklist generation")
        ipv4_blocklist = []
        ipv6_blocklist = []
        
        # Fetch from all sources
        sources = [
            self.fetch_emerging_threats,
            self.fetch_binary_defense,
            self.fetch_abuseipdb
        ]
        
        for source in sources:
            try:
                ipv4_data, ipv6_data = source()
                ipv4_blocklist.extend(ipv4_data)
                ipv6_blocklist.extend(ipv6_data)
            except Exception as e:
                self.logger.error(f"Error fetching from {source.__name__}: {e}")
                continue
        
        self.logger.info(f"Total raw entries collected: {len(ipv4_blocklist)} IPv4, {len(ipv6_blocklist)} IPv6")
        
        if not ipv4_blocklist and not ipv6_blocklist:
            raise BlocklistGeneratorError("No valid entries found from any source")
        
        # Convert to CIDR and filter
        ipv4_cidr_list = self._convert_to_cidr_v4(ipv4_blocklist) if ipv4_blocklist else []
        ipv6_cidr_list = self._convert_to_cidr_v6(ipv6_blocklist) if ipv6_blocklist else []
        
        ipv4_deduplicated = self._deduplicate_and_filter_list_v4(ipv4_cidr_list) if ipv4_cidr_list else []
        ipv6_deduplicated = self._deduplicate_and_filter_list_v6(ipv6_cidr_list) if ipv6_cidr_list else []
        
        ipv4_filtered = self._apply_whitelist_filter_v4(ipv4_deduplicated) if ipv4_deduplicated else []
        ipv6_filtered = self._apply_whitelist_filter_v6(ipv6_deduplicated) if ipv6_deduplicated else []
        
        self.logger.info(f"Final blocklist contains {len(ipv4_filtered)} IPv4 and {len(ipv6_filtered)} IPv6 entries")
        return ipv4_filtered, ipv6_filtered

    def _create_nft_rule_file_dual(self, ipv4_list: List[ipaddress.IPv4Network], ipv6_list: List[ipaddress.IPv6Network]) -> str:
        """
        Create nftables rule file with both IPv4 and IPv6 blocklists.
        
        Args:
            ipv4_list: List of IPv4Network objects
            ipv6_list: List of IPv6Network objects
            
        Returns:
            Path to the created temporary file
        """
        total_entries = len(ipv4_list) + len(ipv6_list)
        self.logger.info(f"Creating nftables rule file with {len(ipv4_list)} IPv4 and {len(ipv6_list)} IPv6 entries")
        
        if self.dry_run:
            self.logger.info("DRY RUN: Would create nftables rule file")
            self.logger.info(f"DRY RUN: File would contain {len(ipv4_list)} IPv4 and {len(ipv6_list)} IPv6 CIDR entries")
            if ipv4_list:
                sample_ipv4 = [str(c) for c in ipv4_list[:3]]
                self.logger.info(f"DRY RUN: Sample IPv4 entries: {sample_ipv4}")
            if ipv6_list:
                sample_ipv6 = [str(c) for c in ipv6_list[:3]]
                self.logger.info(f"DRY RUN: Sample IPv6 entries: {sample_ipv6}")
            return tempfile.mktemp(suffix="-dry-run-blocklist.nft")  # nosec B306 - dry run only
        
        nft_content = ""
        
        # IPv4 set
        if ipv4_list:
            nft_content += f"""
table ip {self.config.NFT_TABLE} {{
    set {self.config.NFT_SET_IPV4} {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {", ".join(str(cidr) for cidr in ipv4_list)} }}
    }}
}}
"""
        
        # IPv6 set
        if ipv6_list:
            nft_content += f"""
table ip6 {self.config.NFT_TABLE} {{
    set {self.config.NFT_SET_IPV6} {{
        type ipv6_addr
        flags interval
        auto-merge
        elements = {{ {", ".join(str(cidr) for cidr in ipv6_list)} }}
    }}
}}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".nft") as temp_file:
            temp_file.write(nft_content)
            self.logger.info(f"Created temporary nftables file: {temp_file.name}")
            return temp_file.name

    def _ensure_nft_sets_exist(self) -> None:
        """Ensure both IPv4 and IPv6 nftables sets exist."""
        if self.dry_run:
            self.logger.info("DRY RUN: Would ensure nftables sets exist")
            return
        
        # Create IPv4 set
        self._ensure_nft_set_exists_single(self.config.NFT_SET_IPV4, "ipv4_addr", "ip")
        
        # Create IPv6 set
        self._ensure_nft_set_exists_single(self.config.NFT_SET_IPV6, "ipv6_addr", "ip6")
    
    def _ensure_nft_set_exists_single(self, set_name: str, addr_type: str, table_family: str) -> None:
        """Ensure a single nftables set exists."""
        check_command = ["sudo", "nft", "list", "set", table_family, self.config.NFT_TABLE, set_name]
        try:
            result = subprocess.run(
                check_command, 
                check=False,
                timeout=self.config.NFT_TIMEOUT, 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0:
                self.logger.info(f"Set {set_name} already exists")
            else:
                self.logger.info(f"Set {set_name} does not exist, creating it")
                create_command = [
                    "sudo", "nft", "add", "set", table_family, self.config.NFT_TABLE, set_name,
                    f"{{ type {addr_type}; flags interval; auto-merge; }}"
                ]
                result = subprocess.run(
                    create_command,
                    check=True,
                    timeout=self.config.NFT_TIMEOUT,
                    capture_output=True,
                    text=True
                )
                self.logger.info(f"Successfully created nftables set {set_name}")
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Error managing nftables set {set_name}: {e.stderr}"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e

    def _flush_nft_sets(self) -> None:
        """Flush both IPv4 and IPv6 nftables sets."""
        if self.dry_run:
            self.logger.info("DRY RUN: Would flush existing nftables sets")
            return
        
        # Ensure sets exist first
        self._ensure_nft_sets_exist()
        
        # Flush IPv4 set
        self._flush_nft_set_single(self.config.NFT_SET_IPV4, "ip")
        
        # Flush IPv6 set
        self._flush_nft_set_single(self.config.NFT_SET_IPV6, "ip6")

    def _flush_nft_set_single(self, set_name: str, table_family: str) -> None:
        """Flush a single nftables set."""
        self.logger.info(f"Flushing {table_family} nftables set {set_name}")
        try:
            command = ["sudo", "nft", "flush", "set", table_family, self.config.NFT_TABLE, set_name]
            result = subprocess.run(
                command, 
                check=True, 
                timeout=self.config.NFT_TIMEOUT, 
                capture_output=True, 
                text=True
            )
            self.logger.info(f"Successfully flushed {table_family} nftables set {set_name}")
        except subprocess.CalledProcessError as e:
            error_msg = f"Error flushing {table_family} nftables set {set_name}: {e.stderr}"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e

    def _apply_nft_rule_file_dual(self, filename: str) -> None:
        """Apply nftables rule file with dual-stack support."""
        if self.dry_run:
            self.logger.info(f"DRY RUN: Would apply nftables rule file: {filename}")
            self.logger.info("DRY RUN: Would flush existing sets and apply new rules")
            try:
                with open(filename, 'r') as f:
                    content_preview = f.read()[:500]
                    self.logger.info(f"DRY RUN: Rule file preview:\n{content_preview}...")
            except Exception as e:
                self.logger.error(f"Error reading rule file for dry run: {e}")
            return
        
        self.logger.info(f"Applying nftables rule file: {filename}")
        
        # Validate filename to prevent path traversal
        if not os.path.abspath(filename).startswith(tempfile.gettempdir()):
            raise NFTConfigError("Invalid nftables rule file path")
        
        # First flush existing sets
        self._flush_nft_sets()
        
        # Apply new rule file
        try:
            command = ["sudo", "nft", "-f", filename]
            result = subprocess.run(  # nosec B603 - controlled input, no shell
                command, 
                check=True, 
                timeout=self.config.NFT_TIMEOUT, 
                capture_output=True, 
                text=True
            )
            self.logger.info("Successfully applied nftables rules")
        except subprocess.CalledProcessError as e:
            error_msg = f"Error applying nftables rules: {e.stderr}"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            error_msg = "Timeout while applying nftables rules"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e

    def run(self) -> None:
        """Main execution method."""
        self.logger.info("=== Starting VyOS IP Blocklist Generation ===")
        
        try:
            ipv4_blocklist, ipv6_blocklist = self.generate_blocklist()
            
            nft_filename = None
            try:
                nft_filename = self._create_nft_rule_file_dual(ipv4_blocklist, ipv6_blocklist)
                self._apply_nft_rule_file_dual(nft_filename)
                
                total_entries = len(ipv4_blocklist) + len(ipv6_blocklist)
                if self.dry_run:
                    self.logger.info("DRY RUN: Blocklist generation completed successfully")
                    self.logger.info(f"DRY RUN: Would have applied {len(ipv4_blocklist)} IPv4 and {len(ipv6_blocklist)} IPv6 entries")
                else:
                    self.logger.info("Blocklist successfully applied to nftables")
                    self.logger.info(f"Applied {len(ipv4_blocklist)} IPv4 and {len(ipv6_blocklist)} IPv6 entries")
                    
            finally:
                if nft_filename and os.path.exists(nft_filename) and not self.dry_run:
                    os.remove(nft_filename)
                    self.logger.debug(f"Cleaned up temporary file: {nft_filename}")
                    
        except Exception as e:
            self.logger.error(f"Fatal error: {e}")
            raise
        finally:
            self.session.close()
        
        self.logger.info("=== Blocklist generation completed successfully ===")


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Generate and apply VyOS IP blocklist from threat intelligence sources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          # Generate and apply blocklist
  %(prog)s --dry-run                # Show what would be done
  %(prog)s --verbose                # Enable debug logging
  %(prog)s --whitelist /path/to/whitelist.txt  # Use custom whitelist file
        """
    )
    parser.add_argument(
        '--dry-run', 
        action='store_true',
        help='Show what would be done without making changes'
    )
    parser.add_argument(
        '--verbose', '-v', 
        action='store_true',
        help='Enable verbose (debug) logging'
    )
    parser.add_argument(
        '--whitelist', 
        type=str,
        help='Path to whitelist file (default: /config/scripts/whitelist.txt)'
    )
    
    args = parser.parse_args()
    
    try:
        generator = BlocklistGenerator(
            dry_run=args.dry_run, 
            verbose=args.verbose,
            whitelist_file=args.whitelist
        )
        generator.run()
        return 0
    except KeyboardInterrupt:
        logging.getLogger(__name__).info("Interrupted by user")
        return 130
    except Exception as e:
        logging.getLogger(__name__).error(f"Fatal error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())