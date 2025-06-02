# Python Firewall Manager

A powerful Python-based firewall management tool that provides an easy-to-use interface for managing iptables rules and ipsets on Linux systems. This tool allows for country-based IP whitelisting, custom IP management, and simplified firewall rule administration.

## Features

- Enable/disable firewall with sensible default policies
- Country-based IP whitelisting (automatically fetches and updates country IP ranges)
- Custom IP whitelist and blacklist management
- Support for loading IPs from files
- Custom iptables rule management
- Real-time firewall status monitoring
- Automatic dependency checking and installation

## Prerequisites

- Linux operating system
- Python 3.x
- Root privileges (sudo)
- Required packages (automatically installed if missing):
  - iptables
  - ipset
  - Python requests library

## Installation

1. Clone or download this repository
2. Make the script executable:
   ```bash
   chmod +x firewall_manager.py
   ```
3. Run the dependency check:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --install-deps
   ```

## Usage

### Basic Commands

1. Enable firewall (with country whitelist):
   ```bash
   sudo python3 /root/fw/firewall_manager.py --enable IR  # Replace IR with desired country code
   ```

2. Enable firewall (without country whitelist):
   ```bash
   sudo python3 /root/fw/firewall_manager.py --enable
   ```

3. Enable firewall without allowing SSH connections (use with caution):
   ```bash
   sudo python3 /root/fw/firewall_manager.py --enable --disable-ssh
   ```

4. Enable firewall and load IPs from whitelist.txt (can be combined with other options):
   ```bash
   sudo python3 /root/fw/firewall_manager.py --whitelist --enable IR --disable-ssh
   ```

5. Disable firewall:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --disable
   ```

6. Show firewall status:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --status
   ```

### IP Management

1. Update country IP list:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --update-country-ips IR  # Replace IR with desired country code
   ```

2. Add single IP to whitelist/blacklist:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --add-ip 1.2.3.4 whitelist
   sudo python3 /root/fw/firewall_manager.py --add-ip 5.6.7.8 blacklist
   ```

3. Remove IP from whitelist/blacklist:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --remove-ip 1.2.3.4 whitelist
   ```

4. Add IPs from file:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --add-ips-from-file /path/to/file.txt whitelist
   ```

5. Load IPs from default whitelist file (whitelist.txt):
   ```bash
   sudo python3 /root/fw/firewall_manager.py --whitelist
   ```

6. Load IPs from default blacklist file (blacklist.txt):
   ```bash
   sudo python3 /root/fw/firewall_manager.py --blacklist
   ```

### Custom Rules

Add custom iptables rules:
```bash
sudo python3 /root/fw/firewall_manager.py --add-custom-rule "INPUT -p tcp --dport 80 -j ACCEPT"
```

Remove custom rules:
```bash
sudo python3 /root/fw/firewall_manager.py --remove-custom-rule "INPUT -p tcp --dport 80 -j ACCEPT"
```

## Default Configuration

- Default SSH port: 22 (configurable in the script)
- Default whitelist file: `whitelist.txt` in the same directory
- Default blacklist file: `blacklist.txt` in the same directory
- IP lists cache directory: `ip_lists/`
- Default policies:
  - INPUT: DROP
  - FORWARD: DROP
  - OUTPUT: ACCEPT

## IPSet Types

The script manages three types of ipsets:
- `country_whitelist`: For country-based IP ranges
- `user_defined_whitelist`: For manually whitelisted IPs
- `user_defined_blacklist`: For manually blacklisted IPs

## Security Notes

1. Always backup your existing firewall rules before using this tool
2. Test the firewall configuration in a controlled environment first
3. Ensure SSH access is properly configured to prevent lockout
4. Use `sudo netfilter-persistent save` to persist rules across reboots

## Troubleshooting

If you get locked out:
1. Access the server physically or through out-of-band management
2. Disable the firewall:
   ```bash
   sudo python3 /root/fw/firewall_manager.py --disable
   ```

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit pull requests.
