# VyOS IP Blocklist Generator

A Python script that automatically fetches and applies IP blocklists from multiple threat intelligence sources to VyOS firewall using nftables.

## Features

- **Multiple Sources**: Fetches blocklists from:
  - Emerging Threats
  - Binary Defense
  - AbuseIPDB (optional, requires API key)
- **Automatic Processing**: Validates IPs, converts to CIDR format, and deduplicates entries
- **VyOS Integration**: Generates and applies nftables rules directly to VyOS
- **Dry Run Mode**: Test the script without making changes
- **Comprehensive Logging**: Detailed logs with file and console output
- **Error Handling**: Robust error handling with timeouts and retries

## Requirements

- VyOS router with nftables support
- Python 3.6+
- Internet connectivity for fetching blocklists

## Installation

1. Clone or download the script to your VyOS router:
```bash
sudo mkdir -p /config/scripts
sudo wget -O /config/scripts/generate_blocklist.py https://raw.githubusercontent.com/productsupcom/vyos-ipblock/main/generate_blocklist.py
sudo chmod +x /config/scripts/generate_blocklist.py
```

2. Install Python dependencies:
```bash
pip3 install requests
```

## Configuration

### 1. Set up AbuseIPDB API Key (Optional)

Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/api) and set it:

```bash
# Method 1: Environment file (recommended)
sudo mkdir -p /config/scripts
echo "ABUSEIPDB_API_KEY=your-api-key-here" | sudo tee /config/scripts/blocklist.env
sudo chmod 600 /config/scripts/blocklist.env

# Method 2: Add to profile
echo 'export ABUSEIPDB_API_KEY="your-api-key-here"' >> ~/.bashrc
source ~/.bashrc
```

### 2. VyOS Firewall Configuration

Create the nftables structure and firewall rules:

```bash
# Enter configuration mode
configure

# Create the nftables set (will be populated by the script)
set firewall group network-group threats-blocklist description 'Threats Blocklist'

# Add firewall rule to block the IPs
set firewall ipv4 name WAN-CLIENTS rule 30 action 'drop'
set firewall ipv4 name WAN-CLIENTS rule 30 description 'Drop Threats'
set firewall ipv4 name WAN-CLIENTS rule 30 log
set firewall ipv4 name WAN-CLIENTS rule 30 source group network-group 'threats-blocklist'

# Commit the configuration
commit
save
exit
```

## Usage

### Manual Execution

```bash
# Basic run
python3 /config/scripts/generate_blocklist.py

# Test without making changes
python3 /config/scripts/generate_blocklist.py --dry-run

# Verbose output
python3 /config/scripts/generate_blocklist.py --verbose

# Dry run with verbose output
python3 /config/scripts/generate_blocklist.py --dry-run --verbose
```

### With Environment File

```bash
source /config/scripts/blocklist.env
python3 /config/scripts/generate_blocklist.py
```

### Automated Execution

Set up a scheduled task to update the blocklist every 6 hours:

```bash
configure
set system task-scheduler task update_blacklists executable path '/config/scripts/update_blocklist.sh'
set system task-scheduler task update_blacklists interval '6h'
commit
save
```

Create the wrapper script:
```bash
sudo tee /config/scripts/update_blocklist.sh << 'EOF'
#!/bin/bash
cd /config/scripts
source blocklist.env 2>/dev/null || true
python3 generate_blocklist.py >> /var/log/blocklist_cron.log 2>&1
EOF
sudo chmod +x /config/scripts/update_blocklist.sh
```

## Command Line Options

- `--dry-run`: Show what would be done without making changes
- `--verbose`, `-v`: Enable verbose logging (debug level)
- `--help`, `-h`: Show help message

## Logging

The script creates detailed logs in:
- Console output (stdout)
- `/config/scripts/blocklist.log` (when run manually)
- `/var/log/blocklist_cron.log` (when run via cron)

Log levels:
- **INFO**: Normal operation messages
- **WARNING**: Non-fatal issues (e.g., missing API key)
- **ERROR**: Errors that prevent operation
- **DEBUG**: Detailed debugging info (use `--verbose`)

## Troubleshooting

### Common Issues

1. **Permission denied when applying nftables rules**
   ```bash
   # Ensure the script runs with sudo privileges
   sudo python3 /config/scripts/generate_blocklist.py
   ```

2. **No entries found**
   - Check internet connectivity
   - Verify URLs are accessible
   - Run with `--verbose` for debugging

3. **AbuseIPDB not working**
   - Verify API key is set correctly
   - Check API quota limits
   - The script will continue without AbuseIPDB if key is missing

4. **nftables errors**
   - Ensure VyOS firewall is properly configured
   - Check that the network group exists
   - Verify nftables service is running

### Testing

Always test with dry-run first:
```bash
python3 /config/scripts/generate_blocklist.py --dry-run --verbose
```

### Manual nftables verification

Check if the set was created and populated:
```bash
sudo nft list set vyos_filter N_threats-blocklist
```

## File Structure

```
/config/scripts/
├── generate_blocklist.py    # Main script
├── blocklist.env           # Environment variables (optional)
├── update_blocklist.sh     # Cron wrapper script
└── blocklist.log          # Log file
```

## Security Notes

- API keys are stored in files with restricted permissions (600)
- The script requires sudo privileges to modify nftables
- Logs may contain sensitive information - protect accordingly
- Regular updates ensure fresh threat intelligence

## Contributing

This script can be improved in several ways:
- Add more threat intelligence sources
- Implement IPv6 support
- Add configuration file support
- Optimize deduplication (currently done by both script and nftables)

## License

[Your chosen license]

## Disclaimer

This script is provided as-is. Test thoroughly in your environment before production use. The authors are not responsible for any network disruptions or false positives.