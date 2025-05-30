#sudo ./firewall_manager.py --update-country-ips IR
#sudo ./firewall_manager.py --enable IR
#!/usr/bin/env python3

import subprocess
import argparse
import os
import sys
import shutil # For shutil.which
import time

# --- Configuration ---
APP_NAME = "Python Firewall Manager"
VERSION = "0.1.0"

# IPSet names
COUNTRY_IPSET_NAME = "country_whitelist"
USER_WHITELIST_IPSET_NAME = "user_defined_whitelist"
USER_BLACKLIST_IPSET_NAME = "user_defined_blacklist"
IPSET_TYPES = [COUNTRY_IPSET_NAME, USER_WHITELIST_IPSET_NAME, USER_BLACKLIST_IPSET_NAME]

# Default whitelist file
DEFAULT_WHITELIST_FILE = "whitelist.txt"
IP_LIST_DOWNLOAD_DIR = "ip_lists" # Directory to store downloaded IP lists

# SSH Port (ensure this is your correct SSH port)
SSH_PORT = 22

# Paths for iptables-persistent
IPTABLES_RULES_FILE = "/etc/iptables/rules.v4"
IPSET_RULES_FILE = "/etc/iptables/ipsets.conf"

# --- Helper Functions ---

def run_command(command, shell=False, check=True):
    """Executes a shell command."""
    if not isinstance(command, list) and not shell:
        print(f"Warning: Command '{' '.join(command) if isinstance(command, list) else command}' might need shell=True or be split into a list.")
    try:
        print(f"Executing: {' '.join(command) if isinstance(command, list) else command}")
        process = subprocess.run(command, shell=shell, check=check, capture_output=True, text=True)
        if process.stdout:
            print(process.stdout)
        if process.stderr:
            print(f"Stderr: {process.stderr}", file=sys.stderr)
        return process
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {' '.join(command) if isinstance(command,list) else command}\n{e}", file=sys.stderr)
        print(f"Stdout: {e.stdout}", file=sys.stderr)
        print(f"Stderr: {e.stderr}", file=sys.stderr)
        if check: # If check is True, CalledProcessError is raised, so this might not be reached unless check=False.
             # However, if check=True and an error occurs, the script would typically exit.
             # If we want to continue, then 'check' should be False and we'd check process.returncode
            sys.exit(f"Command failed with exit code {e.returncode}")
        return e # Return the exception object if check=False
    except FileNotFoundError:
        print(f"Error: Command '{command[0] if isinstance(command,list) else command.split()[0]}' not found. Is it installed and in PATH?", file=sys.stderr)
        sys.exit(1)


def check_root():
    """Check if the script is running as root."""
    if os.geteuid() != 0:
        print("Error: This script must be run as root (or with sudo).", file=sys.stderr)
        sys.exit(1)

def install_package(package_name):
    """Attempts to install a package using apt."""
    print(f"Attempting to install {package_name}...")
    try:
        run_command(["apt-get", "update", "-y"])
        run_command(["apt-get", "install", "-y", package_name])
        print(f"{package_name} installed successfully.")
    except Exception as e:
        print(f"Failed to install {package_name}. Please install it manually. Error: {e}", file=sys.stderr)
        # Optionally, exit if critical
        # sys.exit(1)


def check_and_install_dependencies():
    """Checks for and installs required system packages."""
    print("Checking dependencies...")
    dependencies = {
        "iptables": "iptables", 
        "ipset": "ipset",
        "iptables-persistent": "iptables-persistent"
    }
    missing_system_deps = []

    for cmd, pkg_name in dependencies.items():
        if not shutil.which(cmd) and cmd != "iptables-persistent":  # Special case for iptables-persistent
            print(f"{cmd} not found.")
            missing_system_deps.append(pkg_name)
        elif cmd == "iptables-persistent":
            # Check if iptables-persistent is installed by checking for its config directory
            if not os.path.exists("/etc/iptables"):
                print("iptables-persistent not found.")
                missing_system_deps.append(pkg_name)

    if missing_system_deps:
        print(f"Missing system dependencies: {', '.join(missing_system_deps)}.")
        # Set DEBIAN_FRONTEND to noninteractive to avoid prompts
        os.environ['DEBIAN_FRONTEND'] = 'noninteractive'
        # Consolidate install commands
        packages_to_install = list(set(missing_system_deps))
        if packages_to_install:
            print(f"Attempting to install: {', '.join(packages_to_install)}")
            try:
                run_command(["apt-get", "update", "-y"])
                install_cmd = ["apt-get", "install", "-y"] + packages_to_install
                run_command(install_cmd)
                print(f"Successfully installed: {', '.join(packages_to_install)}")
            except Exception as e:
                print(f"Failed to install some system packages. Please install them manually: {', '.join(packages_to_install)}. Error: {e}", file=sys.stderr)
                sys.exit(1)

    # Check for Python 'requests' library
    try:
        import requests
    except ImportError:
        print("'requests' Python library not found. Attempting to install via pip...")
        try:
            run_command([sys.executable, "-m", "pip", "install", "requests"], check=True)
            print("'requests' library installed successfully.")
        except Exception as e:
            print(f"Failed to install 'requests' library using pip. Please install it manually (e.g., 'pip install requests'). Error: {e}", file=sys.stderr)
            sys.exit(1)
    print("All dependencies are met.")


def ipset_exists(set_name):
    """Checks if an ipset already exists."""
    result = run_command(["ipset", "list", set_name], check=False) # check=False because it errors if not found
    return result.returncode == 0


def create_ipset(set_name, set_type="hash:net"):
    """Creates an ipset if it doesn't exist."""
    if not ipset_exists(set_name):
        print(f"Creating IPSet: {set_name}")
        run_command(["ipset", "create", set_name, set_type, "-exist"]) # -exist won't error if it exists
    else:
        print(f"IPSet {set_name} already exists. Flushing it.")
        run_command(["ipset", "flush", set_name])


def destroy_ipset(set_name):
    """Destroys an ipset if it exists."""
    if ipset_exists(set_name):
        print(f"Destroying IPSet: {set_name}")
        run_command(["ipset", "destroy", set_name])

# --- Firewall Core Functions ---

def flush_all_rules():
    """Flushes all iptables rules, deletes non-default chains, and zeroes counters."""
    print("Flushing all iptables rules and deleting non-default chains...")
    run_command(["iptables", "-F"]) # Flush all rules from all chains
    run_command(["iptables", "-X"]) # Delete all non-default chains
    run_command(["iptables", "-Z"]) # Zero counters in all chains
    # For IPv6 if needed:
    # run_command(["ip6tables", "-F"])
    # run_command(["ip6tables", "-X"])
    # run_command(["ip6tables", "-Z"])
    print("iptables rules flushed.")

def set_default_policies(input_p="DROP", forward_p="DROP", output_p="ACCEPT"):
    """Sets default policies for iptables chains."""
    print(f"Setting default policies: INPUT={input_p}, FORWARD={forward_p}, OUTPUT={output_p}")
    run_command(["iptables", "-P", "INPUT", input_p])
    run_command(["iptables", "-P", "FORWARD", forward_p])
    run_command(["iptables", "-P", "OUTPUT", output_p])
    print("Default policies set.")

def apply_base_rules():
    """Applies essential base rules (loopback, established/related, SSH)."""
    print("Applying base firewall rules...")
    # Allow loopback traffic
    run_command(["iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"])
    run_command(["iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"])

    # Allow established and related connections
    run_command(["iptables", "-A", "INPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
    run_command(["iptables", "-A", "OUTPUT", "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]) # Good for OUTPUT ACCEPT too

    # Allow SSH
    print(f"Allowing SSH on port {SSH_PORT}")
    run_command(["iptables", "-A", "INPUT", "-p", "tcp", "--dport", str(SSH_PORT), "-j", "ACCEPT"])
    print("Base rules applied.")

def apply_ipset_rules():
    """Applies iptables rules for the ipsets."""
    print("Applying IPSet-based rules...")
    # Blacklist first (insert at the top or early)
    # These rules are better inserted with -I to be at the top of the chain
    run_command(["iptables", "-A", "INPUT", "-m", "set", "--match-set", USER_BLACKLIST_IPSET_NAME, "src", "-j", "DROP"])
    # If you want to block outgoing connections to blacklisted IPs:
    run_command(["iptables", "-A", "OUTPUT", "-m", "set", "--match-set", USER_BLACKLIST_IPSET_NAME, "dst", "-j", "DROP"])


    # Whitelists
    run_command(["iptables", "-A", "INPUT", "-m", "set", "--match-set", COUNTRY_IPSET_NAME, "src", "-j", "ACCEPT"])
    run_command(["iptables", "-A", "INPUT", "-m", "set", "--match-set", USER_WHITELIST_IPSET_NAME, "src", "-j", "ACCEPT"])
    print("IPSet rules applied.")


def save_iptables_rules():
    """Saves current iptables rules using iptables-persistent."""
    print("Saving iptables rules...")
    
    # Create directories if they don't exist
    os.makedirs("/etc/iptables", exist_ok=True)
    
    # Save iptables rules
    run_command(["iptables-save"], shell=False, check=True)
    run_command(["sh", "-c", "iptables-save > /etc/iptables/rules.v4"])
    
    # Save ipset rules
    run_command(["sh", "-c", "ipset save > /etc/iptables/ipsets.conf"])
    
    print("Firewall rules and ipsets saved successfully.")

def create_systemd_service():
    """Creates systemd service for proper firewall restoration on boot."""
    service_content = """[Unit]
Description=Restore firewall rules and ipsets
After=network.target
Before=netfilter-persistent.service

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /root/fw/firewall_manager.py --load-rules
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
"""
    
    service_path = "/etc/systemd/system/fw-restore.service"
    try:
        with open(service_path, 'w') as f:
            f.write(service_content)
        
        print("Created systemd service file.")
        run_command(["systemctl", "daemon-reload"])
        run_command(["systemctl", "enable", "fw-restore.service"])
        print("Enabled fw-restore service. Rules will be restored on boot.")
    except Exception as e:
        print(f"Error creating systemd service: {e}", file=sys.stderr)

def load_iptables_rules():
    """Loads saved iptables rules using iptables-persistent."""
    print("Loading saved iptables rules...")
    
    # First, flush existing rules and sets
    flush_all_rules()
    run_command(["ipset", "flush"], check=False)
    
    # Restore ipsets first
    if os.path.exists(IPSET_RULES_FILE):
        print("Restoring ipsets...")
        run_command(["ipset", "restore", "-f", IPSET_RULES_FILE], check=False)
        # Give a small delay to ensure ipsets are fully restored
        time.sleep(1)
    
    # Then restore iptables rules
    if os.path.exists(IPTABLES_RULES_FILE):
        print("Restoring iptables rules...")
        run_command(["iptables-restore", IPTABLES_RULES_FILE], check=False)
    
    print("Firewall rules and ipsets loaded successfully.")

def enable_firewall(country_code=None):
    """Enables the firewall with the configured rules."""
    print("Enabling firewall...")
    check_root()

    flush_all_rules()
    set_default_policies() # INPUT DROP, FORWARD DROP, OUTPUT ACCEPT

    # Destroy and recreate all managed ipsets to ensure a clean state
    for set_name in IPSET_TYPES:
        destroy_ipset(set_name) # Destroy if exists
        create_ipset(set_name)  # Then recreate it fresh

    apply_base_rules()
    apply_ipset_rules() # These rules now point to empty sets until populated

    if country_code:
        update_country_ips(country_code.lower(), initial_setup=True)

    # Load IPs from default whitelist.txt if it exists
    if os.path.exists(DEFAULT_WHITELIST_FILE):
        print(f"Loading IPs from default whitelist file: {DEFAULT_WHITELIST_FILE}")
        add_ips_from_file_to_set(DEFAULT_WHITELIST_FILE, USER_WHITELIST_IPSET_NAME)

    # Save rules for persistence
    save_iptables_rules()
    
    # Create and enable systemd service for boot-time restoration
    create_systemd_service()

    print("Firewall enabled and rules saved for persistence.")
    print("Rules will be automatically restored on system reboot.")

def disable_firewall():
    """Disables the firewall by flushing rules and setting policies to ACCEPT."""
    print("Disabling firewall...")
    check_root()
    flush_all_rules()
    set_default_policies("ACCEPT", "ACCEPT", "ACCEPT")

    # Optionally destroy ipsets
    for set_name in IPSET_TYPES:
        destroy_ipset(set_name)

    # Save the disabled state
    save_iptables_rules()

    print("Firewall disabled and state saved.")
    print("This state will persist across reboots.")

def remove_systemd_service():
    """Removes the systemd service for firewall restoration."""
    service_name = "fw-restore.service"
    service_path = f"/etc/systemd/system/{service_name}"
    
    try:
        # First disable the service
        run_command(["systemctl", "disable", service_name], check=False)
        print(f"Disabled {service_name}")
        
        # Stop the service
        run_command(["systemctl", "stop", service_name], check=False)
        print(f"Stopped {service_name}")
        
        # Remove the service file
        if os.path.exists(service_path):
            os.remove(service_path)
            print(f"Removed service file: {service_path}")
        
        # Reload systemd
        run_command(["systemctl", "daemon-reload"])
        print("Systemd service removed successfully.")
    except Exception as e:
        print(f"Error removing systemd service: {e}", file=sys.stderr)

def delete_saved_rules():
    """Deletes all saved iptables and ipset rules."""
    print("Deleting saved firewall rules...")
    
    # List of files to delete
    files_to_delete = [
        IPTABLES_RULES_FILE,      # /etc/iptables/rules.v4
        IPSET_RULES_FILE,         # /etc/iptables/ipsets.conf
        "/etc/iptables/rules.v6"  # IPv6 rules if they exist
    ]
    
    for file_path in files_to_delete:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"Deleted: {file_path}")
            except Exception as e:
                print(f"Error deleting {file_path}: {e}", file=sys.stderr)
        else:
            print(f"File not found: {file_path}")
    
    # Try to remove the /etc/iptables directory if it's empty
    try:
        os.rmdir("/etc/iptables")
        print("Removed empty /etc/iptables directory")
    except OSError:
        # Directory not empty or doesn't exist - this is fine
        pass
    
    print("All saved firewall rules have been deleted.")

# --- IP Management Functions ---

def fetch_country_ips(country_code):
    """Fetches IP ranges for a given country code from ipv4.fetus.jp."""
    import requests # Import here to ensure it's available after check_and_install
    url = f"https://ipv4.fetus.jp/{country_code.lower()}.txt"
    print(f"Fetching IP list for country {country_code.upper()} from {url}...")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status() # Raises an exception for bad status codes
        ips = [line.strip() for line in response.text.splitlines() if line.strip() and not line.startswith("#")]

        # Save to local cache
        if not os.path.exists(IP_LIST_DOWNLOAD_DIR):
            os.makedirs(IP_LIST_DOWNLOAD_DIR)
        filepath = os.path.join(IP_LIST_DOWNLOAD_DIR, f"{country_code.lower()}.txt")
        with open(filepath, 'w') as f:
            for ip in ips:
                f.write(f"{ip}\n")
        print(f"Successfully fetched and cached {len(ips)} IP ranges for {country_code.upper()} at {filepath}.")
        return ips
    except requests.RequestException as e:
        print(f"Error fetching IP list for {country_code.upper()}: {e}", file=sys.stderr)
        # Fallback to cached list if available
        filepath = os.path.join(IP_LIST_DOWNLOAD_DIR, f"{country_code.lower()}.txt")
        if os.path.exists(filepath):
            print(f"Using cached IP list from {filepath}")
            with open(filepath, 'r') as f:
                ips = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            return ips
        return None


def update_country_ips(country_code, initial_setup=False):
    """Fetches and updates the country_whitelist IPSet."""
    print(f"Updating IPSet '{COUNTRY_IPSET_NAME}' for country {country_code.upper()}...")
    check_root()

    if not ipset_exists(COUNTRY_IPSET_NAME):
        create_ipset(COUNTRY_IPSET_NAME)
    else: # If it exists, flush it before adding new IPs
         run_command(["ipset", "flush", COUNTRY_IPSET_NAME])


    ips = fetch_country_ips(country_code)
    if ips:
        print(f"Adding {len(ips)} IP ranges to IPSet {COUNTRY_IPSET_NAME}...")
        # Use a temporary set for bulk add if ipset supports 'restore'
        # For simplicity, adding one by one:
        for ip in ips:
            # Check if IP is valid CIDR (basic check)
            if '/' in ip or '.' in ip or ':' in ip: # crude check for ip or cidr
                 run_command(["ipset", "add", COUNTRY_IPSET_NAME, ip, "-exist"], check=False) # -exist to avoid errors if already there
            else:
                print(f"Skipping invalid IP/CIDR: {ip}")
        print(f"IPSet {COUNTRY_IPSET_NAME} updated for country {country_code.upper()}.")
    else:
        print(f"No IPs found or fetched for country {country_code.upper()}. IPSet may be empty or unchanged.")


def add_ip_to_set(ip_address, set_name, direction="input"):
    """Adds a single IP to the specified ipset."""
    check_root()
    target_set = ""
    if set_name.lower() == "whitelist":
        target_set = USER_WHITELIST_IPSET_NAME
    elif set_name.lower() == "blacklist":
        target_set = USER_BLACKLIST_IPSET_NAME
    else: # Allow specifying full ipset name directly
        target_set = set_name

    if not ipset_exists(target_set):
        print(f"IPSet {target_set} does not exist. Creating it.")
        create_ipset(target_set)

    print(f"Adding IP {ip_address} to IPSet {target_set}...")
    run_command(["ipset", "add", target_set, ip_address, "-exist"]) # -exist in case it's already there
    print(f"IP {ip_address} added to {target_set}.")
    # Note: iptables rules using these sets are already in place if firewall is enabled.

def remove_ip_from_set(ip_address, set_name, direction="input"):
    """Removes a single IP from the specified ipset."""
    check_root()
    target_set = ""
    if set_name.lower() == "whitelist":
        target_set = USER_WHITELIST_IPSET_NAME
    elif set_name.lower() == "blacklist":
        target_set = USER_BLACKLIST_IPSET_NAME
    else:
        target_set = set_name

    if not ipset_exists(target_set):
        print(f"IPSet {target_set} does not exist. Cannot remove IP.", file=sys.stderr)
        return

    print(f"Removing IP {ip_address} from IPSet {target_set}...")
    # Use -exist to prevent error if IP isn't in the set
    run_command(["ipset", "test", target_set, ip_address], check=False) # Test first to see if it exists
    result = run_command(["ipset", "del", target_set, ip_address, "-exist"], check=False)
    if result.returncode == 0:
        print(f"IP {ip_address} removed from {target_set}.")
    else:
        # ipset del with -exist still returns non-zero if element did not exist to begin with.
        # We can check the output of ipset test before or just inform.
        print(f"IP {ip_address} was not in {target_set} or could not be removed.")


def add_ips_from_file_to_set(filepath, set_name):
    """Adds IPs from a text file (one IP/CIDR per line) to the specified ipset."""
    check_root()
    if not os.path.exists(filepath):
        print(f"Error: File '{filepath}' not found.", file=sys.stderr)
        return

    if not ipset_exists(set_name):
        print(f"IPSet {set_name} does not exist. Creating it.")
        create_ipset(set_name)

    print(f"Adding IPs from file '{filepath}' to IPSet {set_name}...")
    count = 0
    with open(filepath, 'r') as f:
        for line in f:
            ip = line.strip()
            if ip and not ip.startswith("#"): # Ignore empty lines and comments
                run_command(["ipset", "add", set_name, ip, "-exist"])
                count += 1
    print(f"Added {count} IPs from '{filepath}' to {set_name}.")


# --- Custom IPTables Rule Management ---
# These are direct iptables commands, not managed persistently by this script's enable/disable cycle
# unless you re-add them or use iptables-persistent.

def add_custom_iptables_rule(rule_string):
    """Adds a custom iptables rule. Rule string should be everything after 'iptables '."""
    check_root()
    print(f"Adding custom iptables rule: iptables {rule_string}")
    # Using shell=True here as rule_string can be complex. Be cautious with input.
    run_command(f"iptables {rule_string}", shell=True)
    print("Custom rule added. It will be flushed if the firewall is re-enabled/disabled by this script unless re-added.")

def remove_custom_iptables_rule(rule_string):
    """Removes a custom iptables rule. Rule string should be everything after 'iptables -D '."""
    check_root()
    # Ensure -D is not in the string, as we add it. Or expect full -D rule.
    # For simplicity, assume rule_string is like "INPUT -p tcp --dport 80 -j ACCEPT"
    print(f"Removing custom iptables rule: iptables -D {rule_string}")
    run_command(f"iptables -D {rule_string}", shell=True, check=False) # check=False as it errors if rule doesn't exist
    print("Attempted to remove custom rule.")

# --- Status and Listing ---
def show_status():
    """Shows current iptables rules and ipset lists."""
    check_root()
    print("\n--- Current IPTables Rules (filter table) ---")
    run_command(["iptables", "-L", "-v", "-n", "--line-numbers"])

    print("\n--- Listing Managed IPSets ---")
    for set_name in IPSET_TYPES:
        if ipset_exists(set_name):
            print(f"\n--- IPSet: {set_name} ---")
            run_command(["ipset", "list", set_name])
        else:
            print(f"\nIPSet: {set_name} does not exist.")

# --- Main Execution ---
def main():
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{VERSION} - A Python tool to manage iptables and ipsets.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--install-deps", action="store_true", help="Check and attempt to install dependencies (iptables, ipset, iptables-persistent, requests).")

    group_action = parser.add_argument_group('Firewall Actions')
    group_action.add_argument("--enable", metavar="COUNTRY_CODE", nargs='?', const="NO_COUNTRY",
                              help="Enable firewall. Optionally provide a country code (e.g., 'ir', 'us', 'de') to whitelist. "
                                   "If no code, only base rules and user whitelists apply.")
    group_action.add_argument("--disable", action="store_true", help="Disable firewall (flush rules, set policies to ACCEPT).")
    group_action.add_argument("--status", action="store_true", help="Show current firewall rules and managed ipset lists.")

    group_country = parser.add_argument_group('Country Whitelisting')
    group_country.add_argument("--update-country-ips", metavar="COUNTRY_CODE",
                               help="Fetch/update IP list for a country and add to country_whitelist ipset (e.g., 'ir', 'us', 'de').")

    group_manual_ip = parser.add_argument_group('Manual IP Management')
    group_manual_ip.add_argument("--add-ip", nargs=2, metavar=("IP_ADDRESS", "LIST_TYPE"),
                                 help="Add an IP/CIDR to a list. LIST_TYPE can be 'whitelist' or 'blacklist'.\n"
                                      "Example: --add-ip 1.2.3.4 whitelist")
    group_manual_ip.add_argument("--remove-ip", nargs=2, metavar=("IP_ADDRESS", "LIST_TYPE"),
                                 help="Remove an IP/CIDR from a list. LIST_TYPE can be 'whitelist' or 'blacklist'.\n"
                                      "Example: --remove-ip 1.2.3.4 whitelist")
    group_manual_ip.add_argument("--add-ips-from-file", nargs=2, metavar=("FILEPATH", "LIST_TYPE"),
                                 help=f"Add IPs/CIDRs from a file to a list. LIST_TYPE can be 'whitelist' or 'blacklist'.\n"
                                      f"Default user whitelist file '{DEFAULT_WHITELIST_FILE}' is loaded into 'whitelist' on --enable if it exists.")

    group_custom_rules = parser.add_argument_group('Custom IPTables Rules (Advanced)')
    group_custom_rules.add_argument("--add-custom-rule", metavar="'RULE_STRING'",
                                    help="Add a raw iptables rule (e.g., 'INPUT -p udp --dport 53 -j ACCEPT'). Use quotes.")
    group_custom_rules.add_argument("--remove-custom-rule", metavar="'RULE_STRING'",
                                    help="Remove a raw iptables rule (e.g., 'INPUT -p udp --dport 53 -j ACCEPT'). Use quotes.")

    # Add new arguments for iptables-persistent
    parser.add_argument("--save-rules", action="store_true", help="Save current firewall rules for persistence")
    parser.add_argument("--load-rules", action="store_true", help="Load saved firewall rules")

    # Add setup-service and remove-service arguments
    parser.add_argument("--setup-service", action="store_true", 
                       help="Create and enable systemd service for boot-time rule restoration")
    parser.add_argument("--remove-service", action="store_true",
                       help="Remove systemd service for boot-time rule restoration")

    # Add delete-rules argument
    parser.add_argument("--delete-rules", action="store_true",
                       help="Delete all saved firewall rules and ipsets")

    args = parser.parse_args()

    if args.install_deps:
        check_root() # Some install commands might need root
        check_and_install_dependencies()
        print("Dependency check/installation process finished.")
        sys.exit(0)

    # Most operations require dependencies checked/installed first
    # and root privileges.
    if not (args.enable or args.disable or args.status or args.update_country_ips or
            args.add_ip or args.remove_ip or args.add_ips_from_file or
            args.add_custom_rule or args.remove_custom_rule or args.save_rules or 
            args.load_rules or args.setup_service or args.remove_service or
            args.delete_rules):
        if len(sys.argv) == 1:  # No arguments given
            parser.print_help(sys.stderr)
            sys.exit(1)
        # If other args were given but not matched, argparse handles it.

    # Perform dependency check for all actions except help or version.
    # For simplicity, doing it early. If only --install-deps is given, it's handled above.
    check_and_install_dependencies() # Ensure system tools and Python libs are there

    if args.enable:
        country = args.enable if args.enable != "NO_COUNTRY" else None
        enable_firewall(country_code=country)
    elif args.disable:
        disable_firewall()
    elif args.status:
        show_status()
    elif args.update_country_ips:
        update_country_ips(args.update_country_ips)
    elif args.add_ip:
        ip, list_type = args.add_ip
        if list_type.lower() not in ["whitelist", "blacklist"]:
            print("Error: LIST_TYPE for --add-ip must be 'whitelist' or 'blacklist'.", file=sys.stderr)
            sys.exit(1)
        set_name_to_use = USER_WHITELIST_IPSET_NAME if list_type.lower() == "whitelist" else USER_BLACKLIST_IPSET_NAME
        add_ip_to_set(ip, set_name_to_use)
    elif args.remove_ip:
        ip, list_type = args.remove_ip
        if list_type.lower() not in ["whitelist", "blacklist"]:
            print("Error: LIST_TYPE for --remove-ip must be 'whitelist' or 'blacklist'.", file=sys.stderr)
            sys.exit(1)
        set_name_to_use = USER_WHITELIST_IPSET_NAME if list_type.lower() == "whitelist" else USER_BLACKLIST_IPSET_NAME
        remove_ip_from_set(ip, set_name_to_use)
    elif args.add_ips_from_file:
        filepath, list_type = args.add_ips_from_file
        if list_type.lower() not in ["whitelist", "blacklist"]:
            print("Error: LIST_TYPE for --add-ips-from-file must be 'whitelist' or 'blacklist'.", file=sys.stderr)
            sys.exit(1)
        set_name_to_use = USER_WHITELIST_IPSET_NAME if list_type.lower() == "whitelist" else USER_BLACKLIST_IPSET_NAME
        add_ips_from_file_to_set(filepath, set_name_to_use)
    elif args.add_custom_rule:
        add_custom_iptables_rule(args.add_custom_rule)
    elif args.remove_custom_rule:
        remove_custom_iptables_rule(args.remove_custom_rule)
    elif args.save_rules:
        save_iptables_rules()
    elif args.load_rules:
        load_iptables_rules()
    elif args.setup_service:
        check_root()
        create_systemd_service()
    elif args.remove_service:
        check_root()
        remove_systemd_service()
    elif args.delete_rules:
        check_root()
        delete_saved_rules()

if __name__ == "__main__":
    main()