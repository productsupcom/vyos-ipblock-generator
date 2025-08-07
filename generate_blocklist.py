#!/usr/bin/python3

import requests
import re
import ipaddress
import subprocess
import tempfile
import os
import logging
import argparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('blocklist.log')
    ]
)
logger = logging.getLogger(__name__)

def fetch_url(url, headers=None, params=None):
    if headers is None:
        headers = {}
    headers['User-Agent'] = 'curl/7.68.0'

    try:
        logger.info(f"Fetching URL: {url}")
        response = requests.get(url, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        logger.info(f"Successfully fetched {url}, response size: {len(response.text)} bytes")
        return response.text
    except requests.RequestException as e:
        logger.error(f"Error fetching {url}: {e}")
        return ""

def fetch_emerging_threats():
    logger.info("Fetching Emerging Threats blocklist")
    url = 'http://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt'
    data = fetch_url(url)
    filtered_data = filter_lines(data)
    logger.info(f"Emerging Threats: {len(filtered_data)} valid entries found")
    return filtered_data

def fetch_binary_defense():
    logger.info("Fetching Binary Defense blocklist")
    url = 'https://www.binarydefense.com/banlist.txt'
    data = fetch_url(url)
    filtered_data = filter_lines(data)
    logger.info(f"Binary Defense: {len(filtered_data)} valid entries found")
    return filtered_data

def fetch_abuseipdb():
    logger.info("Fetching AbuseIPDB blocklist")
    api_key = os.getenv('ABUSEIPDB_API_KEY')
    
    if not api_key:
        try:
            with open('/config/scripts/abuseipdb.key', 'r') as f:
                api_key = f.read().strip()
        except FileNotFoundError:
            pass
        
    if not api_key:
        logger.warning("ABUSEIPDB_API_KEY not set, skipping AbuseIPDB")
        return []
    
    url = 'https://api.abuseipdb.com/api/v2/blacklist'
    headers = {
        'Key': api_key,
        'Accept': 'text/plain'
    }
    params = {
        'confidenceMinimum': 90
    }
    data = fetch_url(url, headers=headers, params=params)
    filtered_data = filter_lines(data)
    logger.info(f"AbuseIPDB: {len(filtered_data)} valid entries found")
    return filtered_data

def filter_lines(data):
    if not data:
        logger.warning("No data to filter")
        return []
    
    valid_lines = []
    invalid_count = 0
    
    for line in data.splitlines():
        line = line.strip()
        if re.match(r'^(#|;|$)', line):
            continue
        try:
            if '/' in line:
                ip_network = ipaddress.IPv4Network(line, strict=False)
                valid_lines.append(line)
            else:
                ip_address = ipaddress.IPv4Address(line)
                valid_lines.append(line)
        except ValueError:
            invalid_count += 1
            logger.debug(f"Invalid IP/CIDR ignored: {line}")
    
    if invalid_count > 0:
        logger.debug(f"Filtered out {invalid_count} invalid entries")
    
    return valid_lines

def convert_to_cidr(ip_list):
    logger.info(f"Converting {len(ip_list)} entries to CIDR format")
    cidr_list = []
    conversion_errors = 0
    
    for ip in ip_list:
        try:
            if '/' in ip:
                ip_network = ipaddress.ip_network(ip, strict=False)
                cidr_list.append(ip_network)
            else:
                ip_address = ipaddress.ip_address(ip)
                cidr_list.append(ipaddress.ip_network(f"{ip}/32", strict=False))
        except ValueError:
            conversion_errors += 1
            logger.debug(f"Error converting to CIDR: {ip}")
    
    if conversion_errors > 0:
        logger.warning(f"Failed to convert {conversion_errors} entries to CIDR")
    
    logger.info(f"Successfully converted {len(cidr_list)} entries to CIDR")
    return cidr_list

def deduplicate_and_filter_list(cidr_list):
    logger.info(f"Deduplicating and filtering {len(cidr_list)} CIDR entries")
    original_count = len(cidr_list)
    
    # Sort the list by network address and prefix length (smallest to largest)
    cidr_list.sort(key=lambda x: (x.network_address, x.prefixlen))

    # Remove IPs contained within another, less specific CIDR block
    filtered_list = []
    for cidr in cidr_list:
        if not any(cidr.subnet_of(existing) for existing in filtered_list):
            filtered_list.append(cidr)

    removed_count = original_count - len(filtered_list)
    logger.info(f"Removed {removed_count} redundant entries, {len(filtered_list)} unique entries remaining")
    return filtered_list

def generate_blocklist():
    logger.info("Starting blocklist generation")
    blocklist = []
    
    # Fetch from all sources
    blocklist.extend(fetch_emerging_threats())
    blocklist.extend(fetch_binary_defense())
    blocklist.extend(fetch_abuseipdb())

    logger.info(f"Total raw entries collected: {len(blocklist)}")

    # Convert to CIDR and filter invalid ones
    cidr_list = convert_to_cidr(blocklist)

    # Deduplicate and filter the list
    filtered_list = deduplicate_and_filter_list(cidr_list)

    logger.info(f"Final blocklist contains {len(filtered_list)} entries")
    return filtered_list

def create_nft_rule_file(cidr_list, dry_run=False):
    logger.info(f"Creating nftables rule file with {len(cidr_list)} entries")
    
    if dry_run:
        logger.info("DRY RUN: Would create nftables rule file")
        logger.info(f"DRY RUN: File would contain {len(cidr_list)} CIDR entries")
        if cidr_list:
            logger.info(f"DRY RUN: Sample entries: {list(str(c) for c in cidr_list[:5])}")
        return "/tmp/dry-run-blocklist.nft"  # Return dummy filename for dry run
    
    nft_content = """
table ip vyos_filter {
    set N_threats-blocklist {
        type ipv4_addr
        flags interval
        auto-merge
        elements = { %s }
    }
}
""" % ", ".join(str(cidr) for cidr in cidr_list)

    with tempfile.NamedTemporaryFile(delete=False, suffix=".nft") as temp_file:
        temp_file.write(nft_content.encode('utf-8'))
        logger.info(f"Created temporary nftables file: {temp_file.name}")
        return temp_file.name

def flush_nft_map(dry_run=False):
    if dry_run:
        logger.info("DRY RUN: Would flush existing nftables set")
        return
    
    logger.info("Flushing existing nftables set")
    try:
        command = ["sudo", "nft", "flush", "set", "vyos_filter", "N_threats-blocklist"]
        result = subprocess.run(command, check=True, timeout=10, capture_output=True, text=True)
        logger.info("Successfully flushed nftables set")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error flushing nftables set: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        logger.error("Timeout while flushing nftables set")
        raise

def apply_nft_rule_file(filename, dry_run=False):
    if dry_run:
        logger.info(f"DRY RUN: Would apply nftables rule file: {filename}")
        logger.info("DRY RUN: Would flush existing set and apply new rules")
        # In dry run mode, just show what the file contains
        try:
            with open(filename, 'r') as f:
                content_preview = f.read()[:500]  # Show first 500 chars
                logger.info(f"DRY RUN: Rule file preview:\n{content_preview}...")
        except Exception as e:
            logger.error(f"Error reading rule file for dry run: {e}")
        return
    
    logger.info(f"Applying nftables rule file: {filename}")
    
    # First flush existing set
    flush_nft_map(dry_run)

    # Apply new rule file
    try:
        command = ["sudo", "nft", "-f", filename]
        result = subprocess.run(command, check=True, timeout=30, capture_output=True, text=True)
        logger.info("Successfully applied nftables rules")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error applying nftables rules: {e.stderr}")
        raise
    except subprocess.TimeoutExpired:
        logger.error("Timeout while applying nftables rules")
        raise

def main():
    parser = argparse.ArgumentParser(description='Generate and apply VyOS IP blocklist')
    parser.add_argument('--dry-run', action='store_true', 
                       help='Show what would be done without making changes')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    if args.dry_run:
        logger.info("=== DRY RUN MODE - No changes will be made ===")
    
    logger.info("=== Starting VyOS IP Blocklist Generation ===")
    
    try:
        blocklist = generate_blocklist()
        
        if not blocklist:
            logger.error("No valid IPs found in blocklist")
            return 1
        
        nft_filename = None
        try:
            nft_filename = create_nft_rule_file(blocklist, dry_run=args.dry_run)
            apply_nft_rule_file(nft_filename, dry_run=args.dry_run)
            
            if args.dry_run:
                logger.info("DRY RUN: Blocklist generation completed successfully")
                logger.info(f"DRY RUN: Would have applied {len(blocklist)} entries to nftables")
            else:
                logger.info("Blocklist successfully applied to nftables")
        finally:
            if nft_filename and os.path.exists(nft_filename) and not args.dry_run:
                os.remove(nft_filename)
                logger.info(f"Cleaned up temporary file: {nft_filename}")
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        return 1
    
    logger.info("=== Blocklist generation completed successfully ===")
    return 0

if __name__ == "__main__":
    exit(main())