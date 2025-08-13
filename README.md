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

#### Step 1: Create VyOS Network Groups (Manual Setup Required)

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

# Update your existing IPv4 rule to use the new group
set firewall ipv4 name outside-to-inside rule 12 source group network-group 'threats-blocklist-ipv4'
set firewall ipv4 name outside-to-inside rule 12 action 'drop'
set firewall ipv4 name outside-to-inside rule 12 description 'Drop IPv4 threat intelligence IPs'

# Create IPv6 rule for forward filter
set firewall ipv6 forward filter rule 16 action 'drop'
set firewall ipv6 forward filter rule 16 description 'Drop IPv6 threat intelligence IPs'
set firewall ipv6 forward filter rule 16 source group network-group 'threats-blocklist-ipv6'

commit
save
exit
```

#### Step 3: Run the Blocklist Generator

First, run the blocklist generator to create and populate the nftables sets:

```bash
# Create the nftables sets and populate them with threat intelligence
vyos-ipblock --verbose

# Verify the sets were created
sudo nft list sets | grep threats-blocklist
```

#### Step 4: Create Sync Script to Populate VyOS Groups

The VyOS network groups you created are empty by default. Create a script to populate them from the nftables sets:

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

#### Step 5: Run the Sync Script

Populate the VyOS groups with threat intelligence:

```bash
# Run the sync script manually
/config/scripts/sync-vyos-threats.sh

# Verify the groups are populated
show firewall group network-group threats-blocklist-ipv4
show firewall group ipv6-network-group threats-blocklist-ipv6
```

#### Step 6: Automate the Sync Process

Set up automatic synchronization after blocklist updates:

```bash
# Add to crontab to run 5 minutes after blocklist updates
echo "5 */6 * * * /config/scripts/sync-vyos-threats.sh >> /var/log/vyos-threats-sync.log 2>&1" | sudo crontab -

# Or add to the blocklist generator systemd service as a post-hook
```

#### Complete Setup Verification

Check that everything is working:

```bash
# 1. Verify nftables sets exist and have data
sudo nft list sets | grep threats-blocklist
sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 | grep elements
sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 | grep elements

# 2. Verify VyOS groups are populated
show firewall group network-group threats-blocklist-ipv4
show firewall group ipv6-network-group threats-blocklist-ipv6

# 3. Check firewall rules are configured
show firewall ipv4 name outside-to-inside rule 12
show firewall ipv6 forward filter rule 16

# 4. Monitor packet counters to see if blocking is working
run show firewall ipv4 name outside-to-inside rule 12
run show firewall ipv6 forward filter rule 16
```

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

#### Step 1: Create VyOS Network Groups (Manual Setup Required)

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

# Update your existing IPv4 rule to use the new group
set firewall ipv4 name outside-to-inside rule 12 source group network-group 'threats-blocklist-ipv4'
set firewall ipv4 name outside-to-inside rule 12 action 'drop'
set firewall ipv4 name outside-to-inside rule 12 description 'Drop IPv4 threat intelligence IPs'

# Create IPv6 rule for forward filter
set firewall ipv6 forward filter rule 16 action 'drop'
set firewall ipv6 forward filter rule 16 description 'Drop IPv6 threat intelligence IPs'
set firewall ipv6 forward filter rule 16 source group network-group 'threats-blocklist-ipv6'

commit
save
exit
```

#### Step 3: Run the Blocklist Generator

First, run the blocklist generator to create and populate the nftables sets:

```bash
# Create the nftables sets and populate them with threat intelligence
vyos-ipblock --verbose

# Verify the sets were created
sudo nft list sets | grep threats-blocklist
```

#### Step 4: Create Sync Script to Populate VyOS Groups

The VyOS network groups you created are empty by default. Create a script to populate them from the nftables sets:

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

#### Step 5: Run the Sync Script

Populate the VyOS groups with threat intelligence:

```bash
# Run the sync script manually
/config/scripts/sync-vyos-threats.sh

# Verify the groups are populated
show firewall group network-group threats-blocklist-ipv4
show firewall group ipv6-network-group threats-blocklist-ipv6
```

#### Step 6: Automate the Sync Process

Set up automatic synchronization after blocklist updates:

```bash
# Add to crontab to run 5 minutes after blocklist updates
echo "5 */6 * * * /config/scripts/sync-vyos-threats.sh >> /var/log/vyos-threats-sync.log 2>&1" | sudo crontab -

# Or add to the blocklist generator systemd service as a post-hook
```

#### Complete Setup Verification

Check that everything is working:

```bash
# 1. Verify nftables sets exist and have data
sudo nft list sets | grep threats-blocklist
sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 | grep elements
sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 | grep elements

# 2. Verify VyOS groups are populated
show firewall group network-group threats-blocklist-ipv4
show firewall group ipv6-network-group threats-blocklist-ipv6

# 3. Check firewall rules are configured
show firewall ipv4 name outside-to-inside rule 12
show firewall ipv6 forward filter rule 16

# 4. Monitor packet counters to see if blocking is working
run show firewall ipv4 name outside-to-inside rule 12
run show firewall ipv6 forward filter rule 16
```

## 📊 Monitoring & Logs

### Log Files
- **Main log**: `/var/log/vyos-ipblock/blocklist.log` (if installed via package)
- **Current directory**: `blocklist.log` (if run manually)

### Log Rotation
The Debian package includes automatic log rotation:
- Daily rotation
- Keep 7 days of logs
- Compress old logs

### Monitoring Commands
```bash
# View recent activity
sudo journalctl -u vyos-ipblock.service -f

# Check service status
sudo systemctl status vyos-ipblock.service
```

### Checking nftables sets
```bash
# Check IPv4 blocklist
sudo nft list set ip vyos_filter N_threats-blocklist-ipv4

# Check IPv6 blocklist (note the N6 prefix)
sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6

# Count IPv4 entries
sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 | grep -c elements || echo "0"

# Count IPv6 entries  
sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 | grep -c elements || echo "0"

# Check if sets exist
sudo nft list sets | grep threats-blocklist
```

## 🔍 Verification & Debugging

### Check if Blocking is Working

#### Step 0: Ensure Sets Exist
```bash
# First, make sure you've run the script at least once
sudo nft list sets | grep threats-blocklist

# If no sets exist, run the script first
vyos-ipblock --verbose

# Then check again
sudo nft list sets | grep threats-blocklist
```

#### Step 1: Verify nftables Sets Have Data
```bash
# Check IPv4 set exists and has entries
sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 | head -20

# Check IPv6 set exists and has entries
sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 | head -20

# Count total entries
echo "IPv4 threats: $(sudo nft list set ip vyos_filter N_threats-blocklist-ipv4 | grep -c elements || echo 0)"
echo "IPv6 threats: $(sudo nft list set ip6 vyos_filter N6_threats-blocklist-ipv6 | grep -c elements || echo 0)"

# List all threat-related sets to check naming
sudo nft list sets | grep threats
```

#### Step 2: Verify Firewall Rules are Active
```bash
# Check your firewall rules and packet counters
run show firewall ipv4 forward filter rule 12
run show firewall ipv6 forward filter rule 16

# Check if rules reference the correct sets
run show firewall ipv4 forward filter
run show firewall ipv6 forward filter
```

#### Step 3: Debug IPv6 Set Name Mismatch
```bash
# Check what IPv6 sets actually exist
sudo nft list sets | grep -i ipv6
sudo nft list sets | grep -i threats

# Your system should show both:
# N_threats-blocklist-ipv4   (IPv4 set)
# N6_threats-blocklist-ipv6  (IPv6 set)

# Check recent logs for IPv6 processing
sudo journalctl -u vyos-ipblock.service | grep -i ipv6 | tail -5
```

#### Step 4: Fix IPv6 Set Name if Needed
If your firewall rule references `N6_threats-blocklist-ipv6` but the script creates `N_threats-blocklist-ipv6`:

```bash
configure

# Option 1: Update firewall rule to match script
set firewall ipv6 forward filter rule 16 source address '!@vyos_filter,N_threats-blocklist-ipv6'

# Option 2: Check what set name the script actually created
# Exit configure mode first
exit

# List actual IPv6 sets
sudo nft list sets | grep -E "(ipv6|threats)"

# Then update the rule accordingly in configure mode
```

#### Step 5: Monitor Real-time Blocking
```bash
# Watch firewall counters in real-time
watch -n 2 'run show firewall ipv4 forward filter rule 12; echo ""; run show firewall ipv6 forward filter rule 16'

# Monitor nftables directly
sudo nft monitor

# Check system logs for dropped packets
sudo journalctl -k | grep -i drop | tail -10
```

### Debugging Common Issues

#### Issue 0: Sets Don't Exist
If you get "No such file or directory" errors:

```bash
# This means you haven't run the script yet
# The package installation doesn't create the sets - only running the script does

# Run the script to create the sets
vyos-ipblock --verbose

# Check if sets were created
sudo nft list sets | grep threats

# If still no sets, check for errors
sudo journalctl -u vyos-ipblock.service | tail -20
```

#### Issue 1: IPv6 Set Name Mismatch
This is a common issue where the script creates sets with different names than expected:

```bash
# Check what IPv6 sets exist
sudo nft list sets | grep -E "(ipv6|threats|blocklist)"

# Check your firewall rule set reference
run show firewall ipv6 forward filter rule 16

# Common set name variations:
# N_threats-blocklist-ipv6  (script default)
# N6_threats-blocklist-ipv6 (some configurations)
# threats-blocklist-ipv6    (simplified)

# Find the correct set name and update your rule
configure
set firewall ipv6 forward filter rule 16 source address '!@vyos_filter,ACTUAL_SET_NAME'
commit
save
```

#### Issue 2: Zero IPv6 Packet Counts
If IPv6 rules show 0 packets:

```bash
# Check if IPv6 is enabled and working
ping6 google.com
sudo sysctl net.ipv6.conf.all.disable_ipv6

# Check if IPv6 traffic flows through your firewall
run show firewall ipv6 forward filter  # Look at default rule

# Verify IPv6 threats exist in source feeds
vyos-ipblock --dry-run --verbose | grep -i ipv6
```

#### Issue 3: Sets are Empty After Update
```bash
# Check if the script found IPv6 threats
sudo journalctl -u vyos-ipblock.service | grep -E "(IPv6|ipv6)" | tail -10

# Verify IPv6 data in source feeds manually
curl -s https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt | grep -c ":"

# Test IPv6 processing manually
python3 -c "
import generate_blocklist
gen = generate_blocklist.BlocklistGenerator(dry_run=True, verbose=True)
ipv4, ipv6 = gen.generate_blocklist()
print(f'Found {len(ipv4)} IPv4 and {len(ipv6)} IPv6 entries')
"
```

## 📈 Performance

### Resource Usage
- **Memory**: ~10-50MB during execution
- **CPU**: Brief spike during CIDR processing (both IPv4 and IPv6)
- **Network**: Only during threat feed downloads
- **Disk**: ~2MB installed size, minimal log growth

### Optimization
- Automatic CIDR deduplication for both IPv4 and IPv6 reduces nftables memory usage
- Separate processing pipelines for IPv4 and IPv6 for efficiency
- Whitelist filtering happens after deduplication for both protocols
- Network requests are optimized with proper timeouts
- Log rotation prevents disk space issues

## 🔐 Security Considerations

### Data Sources
- All threat intelligence sources are reputable and widely used
- No sensitive data is transmitted (only receives public threat feeds)
- API keys are handled securely with proper file permissions

### Network Security
- Whitelist protection prevents accidental blocking of critical infrastructure
- Input validation ensures only valid IP addresses are processed
- Path validation prevents directory traversal attacks

### Operational Security
- Dry-run mode allows safe testing
- Comprehensive logging for audit trails
- Graceful error handling prevents service disruption

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup
```bash
# Install development dependencies
pip install -r requirements.txt
pip install pytest mypy bandit safety

# Run tests
make test

# Build package
make deb-docker
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Emerging Threats** for community threat intelligence
- **Binary Defense** for professional threat feeds  
- **AbuseIPDB** for crowd-sourced abuse data
- **VyOS Community** for the excellent routing platform

## 📞 Support

- **Issues**: [GitHub Issues](https://github.com/productsupcom/vyos-ipblock-generator/issues)
- **Documentation**: This README and inline code documentation
- **Security Issues**: Please report privately to the maintainers

---

**Made with ❤️ for the VyOS community**