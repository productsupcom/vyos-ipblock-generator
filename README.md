# VyOS IP Blocklist Generator

[![Build Status](https://github.com/productsupcom/vyos-ipblock-generator/workflows/Build%20Debian%20Package/badge.svg)](https://github.com/productsupcom/vyos-ipblock-generator/actions)
[![Security Scan](https://github.com/productsupcom/vyos-ipblock-generator/workflows/Test%20VyOS%20Blocklist%20Generator/badge.svg)](https://github.com/productsupcom/vyos-ipblock-generator/actions)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A professional-grade IP blocklist generator for VyOS that automatically fetches, processes, and applies threat intelligence from multiple sources to your VyOS nftables firewall with full IPv4 and IPv6 support.

## ✨ Features

### 🛡️ Multi-Source Threat Intelligence
- **Emerging Threats**: Community-driven threat intelligence
- **Binary Defense**: Professional threat feeds
- **AbuseIPDB**: Crowd-sourced IP abuse database
- **Smart Deduplication**: Automatically removes redundant CIDR blocks
- **CIDR Optimization**: Merges overlapping ranges for efficiency
- **Dual-Stack Support**: Full IPv4 and IPv6 processing

### 🔒 Advanced Security
- **Whitelist Protection**: Prevents blocking of your own networks (IPv4 and IPv6)
- **Input Validation**: All IP addresses and CIDR blocks validated
- **Path Security**: Protection against directory traversal attacks
- **Secure API Handling**: Safe management of authentication tokens

### 🚀 Enterprise Ready
- **Professional Code**: Type hints, comprehensive docstrings, proper error handling
- **Debian Package**: Easy installation with `.deb` package
- **Systemd Integration**: Automatic updates with timer-based scheduling
- **Comprehensive Logging**: Detailed logs with performance metrics
- **Dry-Run Mode**: Safe testing without making changes

### 🔧 VyOS Integration
- **Native nftables**: Direct integration with VyOS firewall
- **Dual-Stack nftables**: Separate IPv4 and IPv6 sets
- **Complete Replacement**: Removes old entries, adds new ones
- **Atomic Updates**: Safe application of blocklist changes
- **Error Recovery**: Graceful handling of API and network failures

## 📦 Installation

### Option 1: Debian Package (Recommended)

Download and install the pre-built `.deb` package:

```bash
# Download the latest release
wget https://github.com/productsupcom/vyos-ipblock-generator/releases/latest/download/vyos-ipblock_1.0.1-1_all.deb

# Install the package
sudo dpkg -i vyos-ipblock_1.0.1-1_all.deb

# Install any missing dependencies
sudo apt-get install -f
```

### Option 2: From Source

```bash
# Clone the repository
git clone https://github.com/productsupcom/vyos-ipblock-generator.git
cd vyos-ipblock-generator

# Install dependencies
pip3 install -r requirements.txt

# Make the script executable
chmod +x generate_blocklist.py
```

## ⚙️ Configuration

### Whitelist Configuration

Protect your own networks from being blocked (supports both IPv4 and IPv6):

```bash
# Edit the whitelist file
sudo nano /config/scripts/whitelist.txt
```

Example whitelist configuration:
```bash
# IPv4 Internal company networks
10.0.0.0/8
192.168.0.0/16
172.16.0.0/12

# IPv4 Critical infrastructure
203.0.113.0/24
198.51.100.0/24

# IPv4 DNS servers
8.8.8.8
8.8.4.4

# IPv6 Networks
2001:db8::/32
fd00::/8
2001:4860:4860::8888/128
```

**Important**: Any IP or subnet that falls within a whitelisted CIDR block will be automatically excluded from blocking. Both IPv4 and IPv6 networks are supported.

### AbuseIPDB API Key (Optional)

For enhanced threat intelligence, configure an AbuseIPDB API key:

1. Get a free API key from [AbuseIPDB](https://www.abuseipdb.com/api)
2. Configure the key:

```bash
# Option 1: Environment variable
export ABUSEIPDB_API_KEY="your-api-key-here"

# Option 2: File (recommended for automation)
echo "your-api-key-here" | sudo tee /config/scripts/abuseipdb.key
```

**Note**: The file should contain only the API key value, not `ABUSEIPDB_API_KEY=value` format.

## 🚀 Usage

### First Run (Important!)

After installation, you must run the script once to create the nftables sets:

```bash
# First, test the installation
vyos-ipblock --dry-run --verbose

# If the test looks good, run it for real to create the sets
vyos-ipblock --verbose

# Verify the sets were created
sudo nft list sets | grep threats-blocklist
```

**Note**: The package installation only installs the files - the nftables sets are created when you first run the script.

### Basic Usage

```bash
# Test run (shows what would be done)
vyos-ipblock --dry-run --verbose

# Generate and apply blocklist once
vyos-ipblock

# Use custom whitelist file
vyos-ipblock --whitelist /path/to/custom/whitelist.txt

# Enable verbose logging
vyos-ipblock --verbose
```

### Automation

#### Systemd Timer (Recommended)
```bash
# Enable automatic updates every 6 hours
sudo systemctl enable --now vyos-ipblock.timer

# Check timer status
sudo systemctl status vyos-ipblock.timer

# View recent runs
sudo journalctl -u vyos-ipblock.service
```

#### Cron Alternative
```bash
# Add to crontab for updates every 6 hours
echo "0 */6 * * * /usr/bin/vyos-ipblock" | sudo crontab -
```

### VyOS Integration

🎉 **Good news!** The .deb package automatically creates the VyOS firewall groups for you during installation. You just need to configure the firewall rules.

#### Step 1: Install the Package (Groups Created Automatically)

When you install the .deb package on VyOS, it automatically creates:
- `threats-blocklist-ipv4` IPv4 network group
- `threats-blocklist-ipv6` IPv6 network group

```bash
# Install the package (groups are created automatically)
sudo dpkg -i vyos-ipblock_1.0.1-1_all.deb
```

#### Step 2: Configure Firewall Rules to Use the Groups

```bash
configure

# Create the IPv4 and IPv6 groups:
set firewall group network-group threats-blocklist-ipv4
set firewall group ipv6-network-group threats-blocklist-ipv6

# Create IPv4 rule using the auto-created network group
set firewall ipv4 forward filter rule 12 action 'drop'
set firewall ipv4 forward filter rule 12 description 'Drop IPv4 threat intelligence IPs'
set firewall ipv4 forward filter rule 12 source group network-group 'threats-blocklist-ipv4'

# Create IPv6 rule using the auto-created network group
set firewall ipv6 forward filter rule 16 action 'drop'
set firewall ipv6 forward filter rule 16 description 'Drop IPv6 threat intelligence IPs'
set firewall ipv6 forward filter rule 16 source group network-group 'threats-blocklist-ipv6'

commit
save
exit
```

#### Step 3: Run the Blocklist Generator

```bash
# Create the nftables sets and populate them with threat intelligence
vyos-ipblock --verbose

# Verify the sets were created
sudo nft list sets | grep threats-blocklist
```

#### Step 4: Install and Run the Sync Script

```bash
# Copy the sync script from examples
sudo cp /usr/share/doc/vyos-ipblock/examples/sync-vyos-threats.sh /config/scripts/
sudo chmod +x /config/scripts/sync-vyos-threats.sh

# Run the sync script to populate the groups
/config/scripts/sync-vyos-threats.sh

# Verify the groups are populated
show firewall group network-group threats-blocklist-ipv4
show firewall group ipv6-network-group threats-blocklist-ipv6
```


## Summary of Required Manual Steps

✅ **Automated by .deb package:**
1. ~~Create VyOS network groups~~ (done automatically)
2. ~~Install sync script~~ (provided in examples)

🔧 **Manual steps required:**
1. **Configure firewall rules and groups** to reference the auto-created groups
2. **Run vyos-ipblock** to create and populate nftables sets


**Much simpler now!** The .deb package handles the VyOS configuration automatically.

## Complete Setup Verification

Check that everything is working:

```bash
# 1. Verify nftables sets exist and have data
sudo nft list sets | grep threats-blocklist
sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 | grep elements
sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 | grep elements

# 2. Check firewall rules are configured
show firewall ipv4 forward filter rule 12
show firewall ipv6 forward filter rule 16

# 3. Monitor packet counters to see if blocking is working
run show firewall ipv4 forward filter rule 12
run show firewall ipv6 forward filter rule 16

# 4. If using VyOS groups, verify they're populated
show firewall group network-group threats-blocklist-ipv4
show firewall group ipv6-network-group threats-blocklist-ipv6
```
