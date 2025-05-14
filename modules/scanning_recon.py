# modules/scanning_recon.py

import subprocess
import os
import sys
import shutil
import re
import argparse
import signal
import time

# --- Configuration ---
# Define command names for easy modification if needed
IWLIST_CMD = "iwlist"
IFCONFIG_CMD = "ifconfig"  # Deprecated, but often still available
IP_CMD = "ip"
KISMET_CMD = "kismet"
WASH_CMD = "wash"
NMCLI_CMD = "nmcli"
SUDO_CMD = "sudo"
# ---------------------

# Global dictionary for managing background/interactive processes launched by this module
# Key: A unique name for the process (e.g., "Kismet", "wash_scan")
# Value: Popen_object
running_processes = {}


def _is_tool_installed(name):
    """Checks if a command-line tool is installed and in PATH."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def _run_command_capture(command_list, use_sudo=False, check=True, timeout=30):
    """Helper to run a command, capture output, and check for errors."""
    cmd = list(command_list)
    if use_sudo and os.geteuid() != 0:
        if not _is_tool_installed(SUDO_CMD):
            return None, f"'{SUDO_CMD}' not found.", 1  # stdout, stderr, retcode
        cmd.insert(0, SUDO_CMD)

    print(f"[*] Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=check, timeout=timeout)
        return result.stdout, result.stderr, result.returncode
    except subprocess.CalledProcessError as e:
        print(f"[-] Command failed: {' '.join(cmd)}")
        return e.stdout, e.stderr, e.returncode
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd[0]}' not found.")
        return None, f"Command '{cmd[0]}' not found.", 127
    except subprocess.TimeoutExpired:
        print(f"[!] Command timed out: {' '.join(cmd)}")
        return None, "Command timed out.", 124
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        return None, str(e), 1


def _start_interactive_tool(tool_name_key, command_list, use_sudo=False):
    """
    Starts an interactive tool (like Kismet UI mode) that takes over the terminal.
    Manages the process in `running_processes`.
    :param tool_name_key: A unique key to identify this process instance (e.g., "Kismet").
    """
    global running_processes
    if tool_name_key in running_processes and running_processes[tool_name_key].poll() is None:
        print(f"[!] {tool_name_key} seems to be already running (PID: {running_processes[tool_name_key].pid}).")
        return running_processes[tool_name_key]

    cmd = list(command_list)
    if use_sudo and os.geteuid() != 0:
        if not _is_tool_installed(SUDO_CMD): return None
        cmd.insert(0, SUDO_CMD)

    tool_display_name = cmd[1] if use_sudo and len(cmd) > 1 else cmd[0]  # Get actual tool command
    print(f"[*] Starting {tool_display_name} (Key: {tool_name_key}): {' '.join(cmd)}")
    print(f"[+] {tool_display_name} will take over the terminal. Follow its on-screen instructions.")
    print(f"[+] Press Ctrl+C (or follow {tool_display_name}'s exit procedure) to stop it.")
    try:
        # For truly interactive tools, Popen without redirecting stdout/stderr is best
        # to let them use the terminal directly.
        process = subprocess.Popen(cmd)
        running_processes[tool_name_key] = process
        return process
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd[0]}' not found.")
        return None
    except Exception as e:
        print(f"[!] Error starting {tool_display_name} (Key: {tool_name_key}): {e}")
        return None


def _stop_interactive_tool(tool_name_key):
    """Stops a tracked interactive tool if it's running, using its key."""
    global running_processes
    if tool_name_key in running_processes:
        process = running_processes[tool_name_key]
        if process and process.poll() is None:  # Check if process object exists and is running
            tool_display_name = process.args[1] if process.args[0] == SUDO_CMD and len(process.args) > 1 else \
            process.args[0]
            print(f"[*] Attempting to stop {tool_display_name} (Key: {tool_name_key}, PID: {process.pid})...")
            try:
                # Send SIGINT first for graceful shutdown
                if os.geteuid() == 0 or process.args[0] != SUDO_CMD:
                    process.send_signal(signal.SIGINT)
                else:  # if sudo'd, send to sudo process
                    os.kill(process.pid, signal.SIGINT)

                process.wait(timeout=5)  # Wait for graceful exit
                print(f"[+] {tool_display_name} (Key: {tool_name_key}) stopped.")
            except subprocess.TimeoutExpired:
                print(
                    f"[!] {tool_display_name} (Key: {tool_name_key}) did not respond to SIGINT, sending SIGTERM/SIGKILL.")
                process.terminate()  # SIGTERM
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()  # SIGKILL
                    process.wait()  # Wait for kill
            except Exception as e:  # Catch any other errors during termination
                print(f"[!] Error stopping {tool_display_name} (Key: {tool_name_key}): {e}. Force killing.")
                process.kill()
                process.wait()
            finally:  # Ensure it's removed from tracking
                del running_processes[tool_name_key]
            return True
        elif process:  # Process object exists but already terminated
            del running_processes[tool_name_key]  # Clean up tracking
    return False


def scan_networks_iwlist(interface):
    """
    Scans for available Wi-Fi networks using iwlist.

    :param interface: The wireless interface to scan with (e.g., "wlan0").
    :return: A list of dictionaries, each representing a found network, or None on error.
    """
    print(f"[*] Scanning for networks on {interface} using {IWLIST_CMD}...")
    if not _is_tool_installed(IWLIST_CMD): return None

    stdout, stderr, retcode = _run_command_capture([IWLIST_CMD, interface, "scan"], use_sudo=True, check=False)

    if retcode != 0 or not stdout:
        print(f"[-] Failed to scan networks on {interface} using {IWLIST_CMD}.")
        if stderr and stderr.strip(): print(f"    Error: {stderr.strip()}")
        return None

    networks = []
    current_network = {}
    cell_pattern = re.compile(r"Cell \d+ - Address: ([\dA-F:]+)")
    essid_pattern = re.compile(r"ESSID:\"(.*)\"")
    channel_pattern = re.compile(r"Channel:(\d+)")  # Basic channel
    frequency_pattern = re.compile(r"Frequency:([\d\.]+) GHz \(Channel (\d+)\)")  # More robust channel
    quality_pattern = re.compile(r"Quality=(\d+/\d+)\s+Signal level=([-\d]+ dBm)")
    encryption_pattern = re.compile(r"Encryption key:(on|off)")
    # More specific WPA/WPA2 detection
    wpa2_psk_pattern = re.compile(r"IE: IEEE 802.11i/WPA2 Version \d+.*?PSK", re.DOTALL)
    wpa_psk_pattern = re.compile(r"IE: WPA Version \d+.*?PSK", re.DOTALL)  # WPA1 PSK

    cell_data_buffer = []  # Buffer lines for a single cell to parse IE later

    for line in stdout.splitlines():
        stripped_line = line.strip()

        cell_match = cell_pattern.search(stripped_line)
        if cell_match:
            if current_network:  # Process previous cell's buffered data
                # Process IEs from buffer for WPA/WPA2
                full_cell_info = "\n".join(cell_data_buffer)
                if wpa2_psk_pattern.search(full_cell_info):
                    current_network["security"] = "WPA2-PSK"
                    current_network["encryption"] = "on"
                elif wpa_psk_pattern.search(full_cell_info):
                    current_network["security"] = "WPA-PSK"
                    current_network["encryption"] = "on"
                elif current_network.get("encryption") == "on" and "security" not in current_network:
                    current_network["security"] = "WEP"  # Or other if encryption is on but no WPA IE
                elif current_network.get("encryption") == "off":
                    current_network["security"] = "Open"

                networks.append(current_network)
            current_network = {"bssid": cell_match.group(1)}
            cell_data_buffer = [stripped_line]
            continue

        if not current_network:
            continue

        cell_data_buffer.append(stripped_line)  # Add to buffer for current cell

        essid_match = essid_pattern.search(stripped_line)
        if essid_match:
            current_network["essid"] = essid_match.group(1)
            continue

        freq_match = frequency_pattern.search(stripped_line)
        if freq_match:
            current_network["frequency"] = freq_match.group(1) + " GHz"
            current_network["channel"] = int(freq_match.group(2))
            continue
        else:
            channel_match = channel_pattern.search(stripped_line)
            if channel_match and "channel" not in current_network:  # Only if not set by freq_match
                current_network["channel"] = int(channel_match.group(1))
                continue

        quality_match = quality_pattern.search(stripped_line)
        if quality_match:
            current_network["quality"] = quality_match.group(1)
            current_network["signal_level"] = quality_match.group(2) + " dBm"
            continue

        enc_match = encryption_pattern.search(stripped_line)
        if enc_match:
            current_network["encryption"] = enc_match.group(1)
            # Security type determined later from IEs for better accuracy
            continue

    if current_network:  # Process the last cell
        full_cell_info = "\n".join(cell_data_buffer)
        if wpa2_psk_pattern.search(full_cell_info):
            current_network["security"] = "WPA2-PSK"
            current_network["encryption"] = "on"
        elif wpa_psk_pattern.search(full_cell_info):
            current_network["security"] = "WPA-PSK"
            current_network["encryption"] = "on"
        elif current_network.get("encryption") == "on" and "security" not in current_network:
            current_network["security"] = "WEP"
        elif current_network.get("encryption") == "off":
            current_network["security"] = "Open"
        networks.append(current_network)

    if networks:
        print(f"[+] Found {len(networks)} networks.")
    else:
        print("[-] No networks found or failed to parse output.")
    return networks


def get_interface_status(interface=None):
    """
    Shows interface status using 'ip addr' (preferred) or 'ifconfig'.

    :param interface: (Optional) Specific interface to show status for.
    :return: String containing the output, or None on error.
    """
    print(f"[*] Getting interface status...")
    output_str = None  # Renamed from 'output' to avoid conflict

    if _is_tool_installed(IP_CMD):
        cmd = [IP_CMD, "addr"]
        if interface:
            cmd.extend(["show", interface])
        print(f"    Using {IP_CMD}...")
        stdout, stderr, retcode = _run_command_capture(cmd, use_sudo=False, check=False)
        if retcode == 0:
            output_str = stdout
        else:
            if stdout and stdout.strip(): print(f"    {IP_CMD} Stdout: {stdout.strip()}")
            if stderr and stderr.strip(): print(f"    {IP_CMD} Stderr: {stderr.strip()}")

    if output_str is None and _is_tool_installed(IFCONFIG_CMD):
        print(f"    {IP_CMD} failed or not available. Trying {IFCONFIG_CMD}...")
        cmd = [IFCONFIG_CMD]
        if interface:
            cmd.append(interface)
        stdout, stderr, retcode = _run_command_capture(cmd, use_sudo=True, check=False)
        if retcode == 0:
            output_str = stdout
        else:
            if stdout and stdout.strip(): print(f"    {IFCONFIG_CMD} Stdout: {stdout.strip()}")
            if stderr and stderr.strip(): print(f"    {IFCONFIG_CMD} Stderr: {stderr.strip()}")

    if output_str:
        print("[+] Interface Status collected.")  # Actual printing handled by GUI or calling script
        return output_str.strip()
    else:
        print("[-] Could not retrieve interface status.")
        return None


def start_kismet_monitor(interface_source):
    """
    Starts Kismet network monitoring.
    Kismet will typically run in its own terminal or UI, or headless.

    :param interface_source: Kismet source string (e.g., "wlan0" or "kismet.conf source line").
    :return: Popen object for Kismet process, or None on failure.
    """
    print(f"[*] Preparing to start Kismet network monitoring with source: {interface_source}")
    if not _is_tool_installed(KISMET_CMD): return None

    # Example for running Kismet headless, logging to kismetdb, without taking over UI.
    # The user would typically connect to Kismet via web UI.
    # For interactive ncurses UI, remove --no-ncurses-ui.
    cmd = [KISMET_CMD, "-c", interface_source, "--no-ncurses-ui", "-s"]  # -s for silent daemon startup

    return _start_interactive_tool("Kismet", cmd, use_sudo=True)


def scan_wps_networks_wash(interface, channel=None, sort_by_rssi=False, timeout_seconds=None):
    """
    Scans for WPS-enabled networks using Wash. This function will run Wash for a specified
    duration (or until interrupted) and then parse its output.

    :param interface: Wireless interface in MONITOR MODE.
    :param channel: (Optional) Specific channel to scan.
    :param sort_by_rssi: (Optional) If True, sort output by RSSI (-s flag).
    :param timeout_seconds: (Optional) Duration in seconds to run wash. If None, runs until Ctrl+C.
    :return: A list of dictionaries, each representing a WPS-enabled network, or None on error.
    """
    global running_processes
    wash_key = "wash_scan"  # Key for process management

    print(f"[*] Scanning for WPS-enabled networks on {interface} using {WASH_CMD}...")
    print(f"[!] Ensure '{interface}' is in MONITOR MODE for Wash.")

    if not _is_tool_installed(WASH_CMD): return None
    if os.geteuid() != 0 and not _is_tool_installed(SUDO_CMD): return None  # Wash needs sudo

    cmd = [WASH_CMD, "-i", interface]
    if channel:
        cmd.extend(["-c", str(channel)])
    if sort_by_rssi:
        cmd.append("-s")

    final_cmd = [SUDO_CMD] + cmd if os.geteuid() != 0 else cmd
    print(f"[*] Executing: {' '.join(final_cmd)}")
    if timeout_seconds:
        print(f"[*] Wash will run for {timeout_seconds} seconds.")
    else:
        print("[*] Wash will run until interrupted (Ctrl+C).")

    wash_proc = None
    parsed_networks = []
    stdout_data, stderr_data = "", ""

    try:
        wash_proc = subprocess.Popen(final_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        running_processes[wash_key] = wash_proc

        try:
            stdout_data, stderr_data = wash_proc.communicate(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            print("[!] Wash scan timed out. Stopping Wash...")
            # _stop_interactive_tool will handle removal from running_processes
            _stop_interactive_tool(wash_key)
            # Try to get any output produced so far
            # Note: communicate() already closes pipes, so read() might not work as expected after timeout.
            # stdout_data = wash_proc.stdout.read() if wash_proc.stdout else "" # This might be empty or raise error
            # stderr_data = wash_proc.stderr.read() if wash_proc.stderr else ""
            # It's better if _stop_interactive_tool can somehow retrieve remaining output, but Popen makes this hard post-communicate().
            # For now, we assume communicate() gets what it can before timeout, or _stop_interactive_tool just kills it.
            # This means stdout_data/stderr_data might be incomplete on timeout.
        finally:
            # Ensure it's removed from tracking if not already handled by _stop_interactive_tool
            if wash_key in running_processes:
                if running_processes[wash_key].poll() is not None:  # If process finished on its own
                    del running_processes[wash_key]

        # Process collected output
        if wash_proc.returncode != 0 and not stdout_data.strip():
            print(f"[-] Wash command failed or produced no output (exit code {wash_proc.returncode}).")
            if stderr_data and stderr_data.strip(): print(f"    Stderr: {stderr_data.strip()}")
            return None

        header_skipped = False
        for line in stdout_data.splitlines():
            line = line.strip()
            if not line or line.startswith("---"):
                continue
            if "BSSID" in line and "Channel" in line and "ESSID" in line:  # Header line
                header_skipped = True
                continue
            if not header_skipped: continue

            parts = re.split(r'\s{2,}', line)
            if len(parts) >= 6:
                try:
                    network = {
                        "bssid": parts[0], "channel": int(parts[1]), "rssi": int(parts[2]),
                        "wps_version": parts[3], "wps_locked": parts[4],
                        "essid": " ".join(parts[5:])
                    }
                    parsed_networks.append(network)
                except (ValueError, IndexError):
                    print(f"[!] Warning: Could not parse Wash line: {line}")

        if parsed_networks:
            print(f"[+] Found {len(parsed_networks)} WPS-enabled networks.")
        else:
            print("[-] No WPS-enabled networks found by Wash or failed to parse output.")
            if stdout_data.strip(): print(f"    Wash Raw Output:\n{stdout_data.strip()}")

        return parsed_networks

    except KeyboardInterrupt:
        print("\n[!] Wash scan interrupted by user.")
        _stop_interactive_tool(wash_key)
        return parsed_networks  # Return what was parsed so far
    except Exception as e:
        print(f"[-] An error occurred during Wash scan: {e}")
        _stop_interactive_tool(wash_key)
        return None
    finally:  # Ensure cleanup if an error occurs before normal removal
        if wash_key in running_processes and wash_proc and wash_proc.poll() is None:
            _stop_interactive_tool(wash_key)


def scan_networks_nmcli():
    """
    Scans for Wi-Fi networks using nmcli.
    :return: A list of dictionaries representing found networks, or None on error.
    """
    print(f"[*] Scanning for Wi-Fi networks using {NMCLI_CMD}...")
    if not _is_tool_installed(NMCLI_CMD): return None

    print(f"[*] Requesting {NMCLI_CMD} to rescan Wi-Fi devices...")
    _run_command_capture([NMCLI_CMD, "device", "wifi", "rescan"], use_sudo=False, check=False)
    time.sleep(3)

    stdout, stderr, retcode = _run_command_capture(
        [NMCLI_CMD, "-f", "IN-USE,BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY", "device", "wifi", "list"],
        use_sudo=False, check=False)

    if retcode != 0 or not stdout:
        print(f"[-] Failed to scan networks using {NMCLI_CMD}.")
        if stderr and stderr.strip(): print(f"    Error: {stderr.strip()}")
        return None

    networks = []
    lines = stdout.strip().splitlines()
    if len(lines) < 2:
        print("[-] No networks found by nmcli or output format unexpected.")
        return networks

    header = lines[0].strip()
    # Field names from the nmcli -f option, in order
    field_names_str = "IN-USE,BSSID,SSID,MODE,CHAN,FREQ,RATE,SIGNAL,BARS,SECURITY"
    field_keys = [f.strip().lower().replace('-', '_') for f in field_names_str.split(',')]

    # Verify header matches expected fields (approximate check)
    header_parts_count = sum(1 for f in field_keys if f.upper().replace('_', '-') in header)
    if header_parts_count < len(field_keys) - 2:  # Allow a couple of mismatches if -f works
        print(
            f"[!] nmcli header mismatch. Expected fields like '{field_names_str}', got '{header}'. Parsing might be inaccurate.")

    for line in lines[1:]:
        line_stripped = line.strip()
        if not line_stripped: continue

        network = {}
        # nmcli with -f uses ':' as a separator, but values can contain ':' (e.g. BSSID).
        # It also escapes colons within fields using '\:'.
        # A robust parser needs to handle this.
        # Let's try a regex that accounts for escaped colons.

        # Split by non-escaped colons. Pattern: (?<!\\):
        # This means "a colon not preceded by a backslash".
        raw_values = re.split(r'(?<!\\):', line_stripped)
        values = [val.replace('\\:', ':').strip() for val in raw_values]

        if len(values) == len(field_keys):
            for i, key in enumerate(field_keys):
                network[key] = values[i]

            # Type conversions for known fields
            if 'chan' in network: network['chan'] = int(network['chan']) if network['chan'].isdigit() else network[
                'chan']
            if 'signal' in network: network['signal'] = int(network['signal']) if network['signal'].isdigit() else \
            network['signal']
            if 'in_use' in network: network['in_use'] = (network['in_use'] == '*')

            networks.append(network)
        else:
            # Fallback: if -f behavior is not as expected, or output is different.
            # Try a less robust space-based split as before (less ideal).
            # This part is complex to make perfectly robust for all nmcli versions/outputs without -f.
            # Since we used -f, if counts don't match, there's a deeper issue.
            print(
                f"[!] Warning: Mismatch in expected fields for nmcli line: {line_stripped}. Expected {len(field_keys)}, got {len(values)} parts.")
            print(f"    Raw parts: {raw_values}")

    if networks:
        print(f"[+] Found {len(networks)} networks via nmcli.")
    else:
        print("[-] No networks found by nmcli or failed to parse output.")
    return networks


# --- Main execution for demonstration ---
def main():
    parser = argparse.ArgumentParser(description="Network Scanning and Reconnaissance Utilities.")
    parser.add_argument("action", choices=[
        "scan_iwlist", "status", "scan_nmcli",
        "kismet_start", "kismet_stop",
        "wash_scan"  # Changed from wash_start to reflect its behavior
    ], help="Action to perform.")
    parser.add_argument("-i", "--interface",
                        help="Network interface to use (e.g., wlan0, wlan0mon). Required for some actions.")
    parser.add_argument("--wash-channel", type=int, help="Channel for Wash scan.")
    parser.add_argument("--wash-sort", action="store_true", help="Sort Wash output by RSSI.")
    parser.add_argument("--wash-timeout", type=int, help="Timeout for Wash scan (seconds).")

    args = parser.parse_args()

    print("=======================================================")
    print("          Network Scanning & Reconnaissance Tool       ")
    print("=======================================================")
    if args.action not in ["kismet_stop"]:
        print("Disclaimer: Educational purposes ONLY. Use responsibly.")
    print("=======================================================\n")

    # Setup signal handler for graceful shutdown of interactive tools
    def signal_handler_main(sig, frame):
        print(f"\n[!] Signal {sig} received. Stopping any running interactive tools...")
        _stop_interactive_tool("Kismet")  # Key used in _start_interactive_tool
        _stop_interactive_tool("wash_scan")  # Key used in scan_wps_networks_wash
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler_main)
    signal.signal(signal.SIGTERM, signal_handler_main)

    if args.action == "scan_iwlist":
        if not args.interface:
            print("[!] Error: Interface (-i/--interface) is required for iwlist scan.")
            sys.exit(1)
        found_nets = scan_networks_iwlist(args.interface)
        if found_nets:
            print("\n[+] iwlist Scan Results:")
            for net in found_nets:
                print(f"  ESSID: {net.get('essid', 'N/A')}, BSSID: {net.get('bssid', 'N/A')}, "
                      f"Channel: {net.get('channel', 'N/A')}, Signal: {net.get('signal_level', 'N/A')}, "
                      f"Security: {net.get('security', 'N/A')}")

    elif args.action == "status":
        status_output = get_interface_status(args.interface)
        if status_output:
            print("\n--- Interface Status ---")
            print(status_output)
            print("------------------------")


    elif args.action == "scan_nmcli":
        found_nets_nmcli = scan_networks_nmcli()
        if found_nets_nmcli:
            print("\n[+] nmcli Scan Results:")
            for net in found_nets_nmcli:
                print(f"  {'*' if net.get('in_use') else ' '} "
                      f"BSSID: {net.get('bssid', 'N/A')}, SSID: {net.get('ssid', 'N/A')}, "
                      f"Ch: {net.get('chan', 'N/A')}, Signal: {net.get('signal', 'N/A')}, "
                      f"Sec: {net.get('security', 'N/A')}")

    elif args.action == "kismet_start":
        if not args.interface:
            print("[!] Error: Interface source (-i/--interface) for Kismet is required.")
            sys.exit(1)
        kismet_proc = start_kismet_monitor(args.interface)  # Using interface as the source string
        if kismet_proc:
            print(f"[+] Kismet started (PID: {kismet_proc.pid}). This script will wait for it to exit.")
            print(
                "    If Kismet runs detached or has its own UI, you may need to stop it manually or use 'kismet_stop'.")
            try:
                kismet_proc.wait()  # Wait for Kismet to exit if it's managed as a child
            except KeyboardInterrupt:
                print("[!] Kismet run interrupted by Ctrl+C in main script.")
            finally:  # Ensure cleanup if wait() is exited for any reason
                _stop_interactive_tool("Kismet")  # Try to stop it

    elif args.action == "kismet_stop":
        if not _stop_interactive_tool("Kismet"):
            print("[!] Kismet was not found running (or not started by this script's session with key 'Kismet').")

    elif args.action == "wash_scan":  # Renamed from wash_start
        if not args.interface:
            print("[!] Error: Interface (-i/--interface) is required for Wash scan.")
            sys.exit(1)
        wps_nets = scan_wps_networks_wash(args.interface, args.wash_channel, args.wash_sort, args.wash_timeout)
        if wps_nets:
            print("\n[+] Wash Scan Results (WPS APs):")
            for net in wps_nets:
                print(f"  BSSID: {net['bssid']}, Chan: {net['channel']}, RSSI: {net['rssi']}, "
                      f"WPS Ver: {net['wps_version']}, Locked: {net['wps_locked']}, ESSID: {net['essid']}")
        # No need for explicit stop button if wash_scan is designed to complete or timeout.
        # The signal handler (_stop_interactive_tool("wash_scan")) covers interruption.

    print("\n[*] Reconnaissance script finished.")


if __name__ == "__main__":
    main()