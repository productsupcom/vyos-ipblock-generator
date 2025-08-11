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
    NFT_SET = 'N_threats-blocklist'


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
        self.whitelist_networks = self._load_whitelist(whitelist_file)
        
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
    
    def fetch_emerging_threats(self) -> List[str]:
        """Fetch blocklist from Emerging Threats."""
        self.logger.info("Fetching Emerging Threats blocklist")
        try:
            data = self._fetch_url(self.config.EMERGING_THREATS_URL)
            filtered_data = self._filter_lines(data)
            self.logger.info(f"Emerging Threats: {len(filtered_data)} valid entries found")
            return filtered_data
        except APIFetchError:
            self.logger.warning("Failed to fetch Emerging Threats data, continuing without it")
            return []
    
    def fetch_binary_defense(self) -> List[str]:
        """Fetch blocklist from Binary Defense."""
        self.logger.info("Fetching Binary Defense blocklist")
        try:
            data = self._fetch_url(self.config.BINARY_DEFENSE_URL)
            filtered_data = self._filter_lines(data)
            self.logger.info(f"Binary Defense: {len(filtered_data)} valid entries found")
            return filtered_data
        except APIFetchError:
            self.logger.warning("Failed to fetch Binary Defense data, continuing without it")
            return []
    
    def fetch_abuseipdb(self) -> List[str]:
        """Fetch blocklist from AbuseIPDB."""
        self.logger.info("Fetching AbuseIPDB blocklist")
        
        api_key = self._get_abuseipdb_key()
        if not api_key:
            self.logger.warning("ABUSEIPDB_API_KEY not available, skipping AbuseIPDB")
            return []
        
        headers = {
            'Key': api_key,
            'Accept': 'text/plain'
        }
        params = {
            'confidenceMinimum': self.config.ABUSEIPDB_CONFIDENCE_MINIMUM
        }
        
        try:
            data = self._fetch_url(self.config.ABUSEIPDB_URL, headers=headers, params=params)
            filtered_data = self._filter_lines(data)
            self.logger.info(f"AbuseIPDB: {len(filtered_data)} valid entries found")
            return filtered_data
        except APIFetchError:
            self.logger.warning("Failed to fetch AbuseIPDB data, continuing without it")
            return []
    
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

    def _filter_lines(self, data: str) -> List[str]:
        """
        Filter and validate IP addresses and CIDR blocks from text data.
        
        Args:
            data: Raw text data containing IP addresses/CIDR blocks
            
        Returns:
            List of valid IP addresses and CIDR blocks
        """
        if not data:
            self.logger.warning("No data to filter")
            return []
        
        valid_lines = []
        invalid_count = 0
        
        for line_num, line in enumerate(data.splitlines(), 1):
            line = line.strip()
            
            # Skip comments and empty lines
            if re.match(r'^(#|;|$)', line):
                continue
            
            if self._is_valid_ip_or_cidr(line):
                valid_lines.append(line)
            else:
                invalid_count += 1
                self.logger.debug(f"Line {line_num}: Invalid IP/CIDR ignored: {line}")
        
        if invalid_count > 0:
            self.logger.debug(f"Filtered out {invalid_count} invalid entries")
        
        return valid_lines
    
    def _is_valid_ip_or_cidr(self, line: str) -> bool:
        """Validate if a line contains a valid IP address or CIDR block."""
        try:
            if '/' in line:
                ipaddress.IPv4Network(line, strict=False)
            else:
                ipaddress.IPv4Address(line)
            return True
        except ValueError:
            return False
    
    def _convert_to_cidr(self, ip_list: List[str]) -> List[ipaddress.IPv4Network]:
        """
        Convert IP addresses and CIDR blocks to IPv4Network objects.
        
        Args:
            ip_list: List of IP addresses and CIDR blocks as strings
            
        Returns:
            List of IPv4Network objects
        """
        self.logger.info(f"Converting {len(ip_list)} entries to CIDR format")
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
                self.logger.debug(f"Error converting to CIDR: {ip}")
        
        if conversion_errors > 0:
            self.logger.warning(f"Failed to convert {conversion_errors} entries to CIDR")
        
        self.logger.info(f"Successfully converted {len(cidr_list)} entries to CIDR")
        return cidr_list
    
    def _deduplicate_and_filter_list(self, cidr_list: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
        """
        Remove duplicate and redundant CIDR blocks.
        
        Args:
            cidr_list: List of IPv4Network objects
            
        Returns:
            Deduplicated list of IPv4Network objects
        """
        self.logger.info(f"Deduplicating and filtering {len(cidr_list)} CIDR entries")
        original_count = len(cidr_list)
        
        # Sort by network address and prefix length
        cidr_list.sort(key=lambda x: (x.network_address, x.prefixlen))
        
        # Remove networks contained within larger blocks
        filtered_list: List[ipaddress.IPv4Network] = []
        for cidr in cidr_list:
            if not any(cidr.subnet_of(existing) for existing in filtered_list):
                filtered_list.append(cidr)
        
        removed_count = original_count - len(filtered_list)
        self.logger.info(f"Removed {removed_count} redundant entries, {len(filtered_list)} unique entries remaining")
        return filtered_list
    
    def _load_whitelist(self, whitelist_file: Optional[str] = None) -> List[ipaddress.IPv4Network]:
        """
        Load whitelist from configuration file.
        
        Args:
            whitelist_file: Optional path to custom whitelist file
            
        Returns:
            List of IPv4Network objects representing whitelisted networks
        """
        whitelist_path = Path(whitelist_file) if whitelist_file else self.config.WHITELIST_PATH
        
        if not whitelist_path.exists():
            self.logger.info(f"No whitelist file found at {whitelist_path}")
            return []
        
        try:
            self.logger.info(f"Loading whitelist from {whitelist_path}")
            content = whitelist_path.read_text().strip()
            
            if not content:
                self.logger.info("Whitelist file is empty")
                return []
            
            whitelist_entries = self._filter_lines(content)
            whitelist_networks = self._convert_to_cidr(whitelist_entries)
            
            self.logger.info(f"Loaded {len(whitelist_networks)} whitelisted networks")
            for network in whitelist_networks:
                self.logger.debug(f"Whitelisted: {network}")
            
            return whitelist_networks
            
        except (OSError, PermissionError) as e:
            self.logger.warning(f"Could not read whitelist file {whitelist_path}: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error processing whitelist file {whitelist_path}: {e}")
            return []
    
    def _is_whitelisted(self, network: ipaddress.IPv4Network) -> bool:
        """
        Check if a network is whitelisted.
        
        Args:
            network: IPv4Network to check
            
        Returns:
            True if the network overlaps with any whitelisted network
        """
        for whitelist_net in self.whitelist_networks:
            # Check if the network is contained within or overlaps with whitelist
            if (network.subnet_of(whitelist_net) or 
                network.supernet_of(whitelist_net) or 
                network.overlaps(whitelist_net)):
                return True
        return False
    
    def _apply_whitelist_filter(self, cidr_list: List[ipaddress.IPv4Network]) -> List[ipaddress.IPv4Network]:
        """
        Filter out whitelisted networks from the blocklist.
        
        Args:
            cidr_list: List of IPv4Network objects to filter
            
        Returns:
            Filtered list with whitelisted networks removed
        """
        if not self.whitelist_networks:
            self.logger.debug("No whitelist configured, skipping whitelist filtering")
            return cidr_list
        
        self.logger.info(f"Applying whitelist filter to {len(cidr_list)} entries")
        original_count = len(cidr_list)
        
        filtered_list = []
        whitelisted_count = 0
        
        for network in cidr_list:
            if self._is_whitelisted(network):
                whitelisted_count += 1
                self.logger.debug(f"Filtered out whitelisted network: {network}")
            else:
                filtered_list.append(network)
        
        self.logger.info(
            f"Whitelist filtering: removed {whitelisted_count} entries, "
            f"{len(filtered_list)} entries remaining"
        )
        
        return filtered_list
    
    def generate_blocklist(self) -> List[ipaddress.IPv4Network]:
        """
        Generate the complete blocklist from all sources.
        
        Returns:
            List of IPv4Network objects representing the final blocklist
        """
        self.logger.info("Starting blocklist generation")
        blocklist = []
        
        # Fetch from all sources
        sources = [
            self.fetch_emerging_threats,
            self.fetch_binary_defense,
            self.fetch_abuseipdb
        ]
        
        for source in sources:
            try:
                data = source()
                blocklist.extend(data)
            except Exception as e:
                self.logger.error(f"Error fetching from {source.__name__}: {e}")
                continue
        
        self.logger.info(f"Total raw entries collected: {len(blocklist)}")
        
        if not blocklist:
            raise BlocklistGeneratorError("No valid entries found from any source")
        
        # Convert to CIDR and filter
        cidr_list = self._convert_to_cidr(blocklist)
        deduplicated_list = self._deduplicate_and_filter_list(cidr_list)
        filtered_list = self._apply_whitelist_filter(deduplicated_list)
        
        self.logger.info(f"Final blocklist contains {len(filtered_list)} entries")
        return filtered_list
    
    def _create_nft_rule_file(self, cidr_list: List[ipaddress.IPv4Network]) -> str:
        """
        Create nftables rule file with the blocklist.
        
        Args:
            cidr_list: List of IPv4Network objects
            
        Returns:
            Path to the created temporary file
        """
        self.logger.info(f"Creating nftables rule file with {len(cidr_list)} entries")
        
        if self.dry_run:
            self.logger.info("DRY RUN: Would create nftables rule file")
            self.logger.info(f"DRY RUN: File would contain {len(cidr_list)} CIDR entries")
            if cidr_list:
                sample_entries = [str(c) for c in cidr_list[:5]]
                self.logger.info(f"DRY RUN: Sample entries: {sample_entries}")
            # Use tempfile for dry run as well to avoid hardcoded paths
            return tempfile.mktemp(suffix="-dry-run-blocklist.nft")  # nosec B306 - dry run only
        
        nft_content = f"""
table ip {self.config.NFT_TABLE} {{
    set {self.config.NFT_SET} {{
        type ipv4_addr
        flags interval
        auto-merge
        elements = {{ {", ".join(str(cidr) for cidr in cidr_list)} }}
    }}
}}
"""
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix=".nft") as temp_file:
            temp_file.write(nft_content)
            self.logger.info(f"Created temporary nftables file: {temp_file.name}")
            return temp_file.name
    
    def _ensure_nft_set_exists(self) -> None:
        """Ensure the nftables set exists, create it if it doesn't."""
        if self.dry_run:
            self.logger.info("DRY RUN: Would ensure nftables set exists")
            return
        
        self.logger.info("Checking if nftables set exists")
        
        # Check if the set exists
        check_command = ["sudo", "nft", "list", "set", self.config.NFT_TABLE, self.config.NFT_SET]
        try:
            result = subprocess.run(
                check_command, 
                check=False,  # Don't fail if set doesn't exist
                timeout=self.config.NFT_TIMEOUT, 
                capture_output=True, 
                text=True
            )
            
            if result.returncode == 0:
                self.logger.info(f"Set {self.config.NFT_SET} already exists")
            else:
                self.logger.info(f"Set {self.config.NFT_SET} does not exist, creating it")
                # Create the set
                create_command = [
                    "sudo", "nft", "add", "set", "ip", self.config.NFT_TABLE, self.config.NFT_SET,
                    "{ type ipv4_addr; flags interval; auto-merge; }"
                ]
                result = subprocess.run(
                    create_command,
                    check=True,
                    timeout=self.config.NFT_TIMEOUT,
                    capture_output=True,
                    text=True
                )
                self.logger.info(f"Successfully created nftables set {self.config.NFT_SET}")
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Error managing nftables set: {e.stderr}"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            error_msg = "Timeout while managing nftables set"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e

    def _flush_nft_set(self) -> None:
        """Flush the existing nftables set."""
        if self.dry_run:
            self.logger.info("DRY RUN: Would flush existing nftables set")
            return
        
        # Ensure the set exists first
        self._ensure_nft_set_exists()
        
        self.logger.info("Flushing existing nftables set")
        try:
            command = ["sudo", "nft", "flush", "set", self.config.NFT_TABLE, self.config.NFT_SET]
            result = subprocess.run(
                command, 
                check=True, 
                timeout=self.config.NFT_TIMEOUT, 
                capture_output=True, 
                text=True
            )
            self.logger.info("Successfully flushed nftables set")
        except subprocess.CalledProcessError as e:
            error_msg = f"Error flushing nftables set: {e.stderr}"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e
        except subprocess.TimeoutExpired as e:
            error_msg = "Timeout while flushing nftables set"
            self.logger.error(error_msg)
            raise NFTConfigError(error_msg) from e

    def _apply_nft_rule_file(self, filename: str) -> None:
        """
        Apply nftables rule file.
        
        Args:
            filename: Path to the nftables rule file
        """
        if self.dry_run:
            self.logger.info(f"DRY RUN: Would apply nftables rule file: {filename}")
            self.logger.info("DRY RUN: Would flush existing set and apply new rules")
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
        
        # First flush existing set
        self._flush_nft_set()
        
        # Apply new rule file - filename comes from our own tempfile creation
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
            blocklist = self.generate_blocklist()
            
            nft_filename = None
            try:
                nft_filename = self._create_nft_rule_file(blocklist)
                self._apply_nft_rule_file(nft_filename)
                
                if self.dry_run:
                    self.logger.info("DRY RUN: Blocklist generation completed successfully")
                    self.logger.info(f"DRY RUN: Would have applied {len(blocklist)} entries to nftables")
                else:
                    self.logger.info("Blocklist successfully applied to nftables")
                    
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