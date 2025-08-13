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

The tool creates nftables sets that need to be synchronized with VyOS network groups. You must manually create the VyOS network groups and firewall rules, then use the sync script to populate them.

#### Step 1: Create VyOS Network Groups

```bash
configure

# Create IPv4 network group
set firewall group network-group threats-blocklist-ipv4 description 'IPv4 Threat Intelligence'

# Create IPv6 network group  
set firewall group ipv6-network-group threats-blocklist-ipv6 description 'IPv6 Threat Intelligence'

commit
save
```

#### Step 2: Configure Firewall Rules to Use the Groups

```bash
configure

# Create IPv4 rule using network group
set firewall ipv4 forward filter rule 12 action 'drop'
set firewall ipv4 forward filter rule 12 description 'Drop IPv4 threat intelligence IPs'
set firewall ipv4 forward filter rule 12 source group network-group 'threats-blocklist-ipv4'

# Create IPv6 rule using network group
set firewall ipv6 forward filter rule 16 action 'drop'
set firewall ipv6 forward filter rule 16 description 'Drop IPv6 threat intelligence IPs'
set firewall ipv6 forward filter rule 16 source group ipv6-network-group 'threats-blocklist-ipv6'

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

#### Step 4: Create Sync Script to Populate VyOS Groups (optional)

```bash
# Create the sync script
cat > /config/scripts/sync-vyos-threats.sh << 'EOF'
#!/bin/bash

echo "Syncing threat intelligence to VyOS network groups..."

# Function to sync IPv4 threats
sync_ipv4_threats() {
    echo "Syncing IPv4 threats..."
    
    # Clear existing IPv4 group
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete firewall group network-group threats-blocklist-ipv4 address 2>/dev/null || true
    
    # Get IPs from nftables set and add to VyOS group (limit to 1000 for performance)
    sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 2>/dev/null | \
        grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' | \
        head -1000 | \
        while read ip; do
            /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group network-group threats-blocklist-ipv4 address "$ip"
        done
    
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
    
    local count=$(sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 2>/dev/null | grep -c elements || echo "0")
    echo "IPv4 threats synced: $count entries"
}

# Function to sync IPv6 threats
sync_ipv6_threats() {
    echo "Syncing IPv6 threats..."
    
    # Clear existing IPv6 group
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper begin
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper delete firewall group ipv6-network-group threats-blocklist-ipv6 address 2>/dev/null || true
    
    # Get IPs from nftables set and add to VyOS group (limit to 1000 for performance)
    sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 2>/dev/null | \
        grep -oE '([0-9a-fA-F:]+:+)+[0-9a-fA-F]+(/[0-9]{1,3})?' | \
        head -1000 | \
        while read ip; do
            /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper set firewall group ipv6-network-group threats-blocklist-ipv6 address "$ip"
        done
    
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper commit
    /opt/vyatta/sbin/vyatta-cfg-cmd-wrapper end
    
    local count=$(sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 2>/dev/null | grep -c elements || echo "0")
    echo "IPv6 threats synced: $count entries"
}

# Run sync functions
sync_ipv4_threats
sync_ipv6_threats

echo "Threat intelligence sync completed"
EOF

chmod +x /config/scripts/sync-vyos-threats.sh
```

#### Step 5: Run the Sync Script and Automate

```bash
# Run the sync script manually
/config/scripts/sync-vyos-threats.sh

# Verify the groups are populated
show firewall group network-group threats-blocklist-ipv4
show firewall group ipv6-network-group threats-blocklist-ipv6

# Add to crontab to run 5 minutes after blocklist updates
echo "5 */6 * * * /config/scripts/sync-vyos-threats.sh >> /var/log/vyos-threats-sync.log 2>&1" | sudo crontab -
```

## Summary of Required Manual Steps

1. **Create VyOS network groups** (threats-blocklist-ipv4 and threats-blocklist-ipv6)
2. **Configure firewall rules** to reference these groups  
3. **Run vyos-ipblock** to create and populate nftables sets
4. **Create and run sync script** to populate VyOS groups from nftables sets
5. **Set up automation** for ongoing synchronization

**Important**: The blocklist generator creates nftables sets, but VyOS firewall rules use network groups. The sync script bridges this gap by copying threat intelligence from nftables sets to VyOS groups.

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