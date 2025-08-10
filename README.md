# VyOS IP Blocklist Generator

[![Build Status](https://github.com/productsupcom/vyos-ipblock-generator/workflows/Build%20Debian%20Package/badge.svg)](https://github.com/productsupcom/vyos-ipblock-generator/actions)
[![Security Scan](https://github.com/productsupcom/vyos-ipblock-generator/workflows/Test%20VyOS%20Blocklist%20Generator/badge.svg)](https://github.com/productsupcom/vyos-ipblock-generator/actions)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A professional-grade IP blocklist generator for VyOS that automatically fetches, processes, and applies threat intelligence from multiple sources to your VyOS nftables firewall.

## ✨ Features

### 🛡️ Multi-Source Threat Intelligence
- **Emerging Threats**: Community-driven threat intelligence
- **Binary Defense**: Professional threat feeds
- **AbuseIPDB**: Crowd-sourced IP abuse database
- **Smart Deduplication**: Automatically removes redundant CIDR blocks
- **CIDR Optimization**: Merges overlapping ranges for efficiency

### 🔒 Advanced Security
- **Whitelist Protection**: Prevents blocking of your own networks
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
- **Complete Replacement**: Removes old entries, adds new ones
- **Atomic Updates**: Safe application of blocklist changes
- **Error Recovery**: Graceful handling of API and network failures

## 📦 Installation

### Option 1: Debian Package (Recommended)

Download and install the pre-built `.deb` package:

```bash
# Download the latest release
wget https://github.com/productsupcom/vyos-ipblock-generator/releases/latest/download/vyos-ipblock_1.0.0-1_all.deb

# Install the package
sudo dpkg -i vyos-ipblock_1.0.0-1_all.deb

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

Protect your own networks from being blocked:

```bash
# Edit the whitelist file
sudo nano /config/scripts/whitelist.txt
```

Example whitelist configuration:
```bash
# Internal company networks
10.0.0.0/8
192.168.0.0/16
172.16.0.0/12

# Critical infrastructure
203.0.113.0/24
198.51.100.0/24

# DNS servers
8.8.8.8
8.8.4.4
```

**Important**: Any IP or subnet that falls within a whitelisted CIDR block will be automatically excluded from blocking.

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

The tool creates nftables rules compatible with VyOS. Use the generated set in your firewall rules:

```bash
# Example VyOS configuration
set firewall name OUTSIDE_IN rule 10 action 'drop'
set firewall name OUTSIDE_IN rule 10 source group address-group 'N_threats-blocklist'
set firewall name OUTSIDE_IN rule 10 description 'Block threat intelligence IPs'
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

# View current blocklist size
sudo nft list set vyos_filter N_threats-blocklist | grep -c elements
```

## 🛠️ Development

### Building from Source

```bash
# Clone and build
git clone https://github.com/productsupcom/vyos-ipblock-generator.git
cd vyos-ipblock-generator

# Build Debian package (requires Docker)
make deb-docker

# Or build natively on Debian/Ubuntu
make deb
```

### Testing

```bash
# Run dry-run tests
make test

# Run the full test suite (requires Python test dependencies)
python -m pytest tests/

# Security scanning
bandit -r generate_blocklist.py
```

### Code Quality

The codebase follows professional standards:
- **Type Hints**: Full type annotation coverage
- **Docstrings**: Comprehensive documentation
- **Error Handling**: Custom exceptions and proper recovery
- **Security**: Bandit compliance and secure coding practices
- **Testing**: Comprehensive test coverage with GitHub Actions

## 🔍 Troubleshooting

### Common Issues

**Package Installation Issues**
```bash
# Fix broken dependencies
sudo apt-get install -f

# Reinstall package
sudo dpkg --purge vyos-ipblock
sudo dpkg -i vyos-ipblock_*.deb
```

**API Access Issues**
```bash
# Test network connectivity
curl -I https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt

# Verify AbuseIPDB key
vyos-ipblock --dry-run --verbose | grep -i abuseipdb
```

**VyOS Integration Issues**
```bash
# Check nftables set
sudo nft list set vyos_filter N_threats-blocklist

# Manual flush if needed
sudo nft flush set vyos_filter N_threats-blocklist
```

**Permission Issues**
```bash
# Ensure proper permissions
sudo chown root:root /config/scripts/
sudo chmod 755 /config/scripts/
sudo chmod 600 /config/scripts/abuseipdb.key
```

### Debug Mode

For detailed troubleshooting:
```bash
# Maximum verbosity
vyos-ipblock --dry-run --verbose

# Check logs
tail -f /var/log/vyos-ipblock/blocklist.log
```

## 📈 Performance

### Resource Usage
- **Memory**: ~10-50MB during execution
- **CPU**: Brief spike during CIDR processing
- **Network**: Only during threat feed downloads
- **Disk**: ~2MB installed size, minimal log growth

### Optimization
- Automatic CIDR deduplication reduces nftables memory usage
- Whitelist filtering happens after deduplication for efficiency
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