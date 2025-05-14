# modules/interface_monitor.py

import subprocess
import shutil
import re
import os
import sys  # For potential future use, not strictly needed now

# --- Configuration ---
AIRMON_NG_COMMAND = "airmon-ng"
SUDO_COMMAND = "sudo"


# ---------------------

def _is_tool_installed(name):
    """Checks if a command-line tool is installed and in PATH."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def _run_airmon_command(airmon_args):
    """
    Helper function to construct and run airmon-ng commands with sudo if needed.
    Returns the CompletedProcess object or None on critical failure before execution.
    """
    if not _is_tool_installed(AIRMON_NG_COMMAND):
        return None

    cmd = []
    # Airmon-ng almost always requires root privileges
    if os.geteuid() != 0:
        if not _is_tool_installed(SUDO_COMMAND):
            print(f"[!] Error: '{SUDO_COMMAND}' is required to run {AIRMON_NG_COMMAND} as non-root.")
            return None
        cmd.append(SUDO_COMMAND)

    cmd.append(AIRMON_NG_COMMAND)
    cmd.extend(airmon_args)

    command_str = ' '.join(cmd)
    print(f"[*] Executing: {command_str}")
    try:
        # Using check=False because airmon-ng can have non-zero exit codes for various reasons
        # that aren't necessarily fatal (e.g., 'check kill' finding no processes).
        # We'll inspect the returncode and output manually.
        result = subprocess.run(cmd, capture_output=True, text=True, check=False,
                                timeout=45)  # Increased timeout slightly
        return result
    except subprocess.TimeoutExpired:
        print(f"[-] Timeout ({45}s) executing: {command_str}")
        return None  # Or a mock CompletedProcess with a specific error code
    except FileNotFoundError:  # Should be caught by _is_tool_installed, but as a safeguard
        print(f"[!] Critical Error: Command '{cmd[0]}' not found during execution attempt.")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred while executing '{command_str}': {e}")
        return None


def enable_monitor(interface, kill_conflicting_processes=True):
    """
    Enables monitor mode on the specified interface using airmon-ng.

    :param interface: The wireless interface (e.g., "wlan0").
    :param kill_conflicting_processes: If True, run 'airmon-ng check kill' first.
    :return: The name of the monitor mode interface (e.g., "wlan0mon") or None on failure.
    """
    print(f"[*] Attempting to enable monitor mode on interface: {interface}")

    if kill_conflicting_processes:
        print("[*] Running 'airmon-ng check kill' to stop potentially interfering processes...")
        kill_result = _run_airmon_command(["check", "kill"])
        if kill_result is None:  # Critical error running command
            print("[-] Failed to execute 'airmon-ng check kill'. Aborting monitor mode enablement.")
            return None
        # 'check kill' can exit 0 or non-0 even if successful in its task (e.g. no processes to kill)
        # We print its output for user information.
        if kill_result.stdout: print(f"    [check kill stdout]: {kill_result.stdout.strip()}")
        if kill_result.stderr: print(f"    [check kill stderr]: {kill_result.stderr.strip()}")
        print("[+] 'airmon-ng check kill' command finished.")
        # We don't necessarily fail if 'check kill' itself had a non-zero exit,
        # as it might just mean no processes were found to kill.

    print(f"[*] Now attempting to start monitor mode on '{interface}'...")
    start_result = _run_airmon_command(["start", interface])

    if start_result is None:  # Critical error running command
        print(f"[-] Failed to execute 'airmon-ng start {interface}'.")
        return None

    # Combine stdout and stderr for parsing as airmon-ng can put info in either
    output = (start_result.stdout or "") + (start_result.stderr or "")

    if start_result.returncode != 0:
        print(f"[-] 'airmon-ng start {interface}' failed with exit code {start_result.returncode}.")
        if output.strip(): print(f"    Output: {output.strip()}")
        # Check if it failed because monitor mode was already enabled
        # This is a common scenario where airmon-ng might exit non-zero.
        already_enabled_match = re.search(r"monitor mode already enabled for\s+(\w+)", output, re.IGNORECASE)
        if already_enabled_match:
            mon_interface_name = already_enabled_match.group(1)
            print(f"[+] Monitor mode was already enabled on '{mon_interface_name}'. Assuming this is the target.")
            return mon_interface_name
        return None  # Failed for other reasons

    # Try to parse the new interface name from airmon-ng's output
    # Order of preference for regex patterns:
    patterns = [
        re.compile(r"monitor mode vif enabled on \[\w+\](\w+)", re.IGNORECASE),
        # Modern: "monitor mode vif enabled on [phyX]wlanYmon"
        re.compile(r"\(monitor mode enabled on (\w+)\)", re.IGNORECASE),  # Legacy: "(monitor mode enabled on wlanXmon)"
        re.compile(r"monitor mode enabled for\s+(\w+)", re.IGNORECASE),
        # Already enabled: "monitor mode enabled for wlanXmon"
        re.compile(rf"\({interface}\)\s+switched to monitor mode", re.IGNORECASE)  # Original interface name used
    ]

    parsed_interface_name = None
    for i, pattern in enumerate(patterns):
        match = pattern.search(output)
        if match:
            if i == 3:  # (wlan0) switched to monitor mode
                parsed_interface_name = interface
                print(f"[+] Monitor mode enabled, interface name '{interface}' likely unchanged (Pattern {i + 1}).")
            else:
                parsed_interface_name = match.group(1)
                print(
                    f"[+] Monitor mode enabled, new/confirmed interface: '{parsed_interface_name}' (Pattern {i + 1}).")
            return parsed_interface_name

    # Fallback if command succeeded (returncode 0) but no pattern matched explicitly
    # This can happen if airmon-ng output changes or if the interface name is very unusual.
    # A common fallback is to assume <interface>mon if interface doesn't already end with 'mon'.
    if not interface.endswith("mon"):
        potential_mon_iface = interface + "mon"
        print(f"[?] Airmon-ng reported success, but new interface name parsing was inconclusive.")
        print(
            f"    Assuming new interface might be '{potential_mon_iface}'. VERIFY MANUALLY using 'iwconfig' or 'ip link'.")
        return potential_mon_iface
    else:  # Original interface already looked like a monitor interface
        print(
            f"[?] Airmon-ng reported success. Original interface '{interface}' already appears to be a monitor interface.")
        print(f"    Assuming '{interface}' is correct. VERIFY MANUALLY.")
        return interface


def disable_monitor(monitor_interface):
    """
    Disables monitor mode on the specified monitor interface using airmon-ng.

    :param monitor_interface: The monitor mode interface (e.g., "wlan0mon").
    :return: True if successful (or if interface already not in monitor mode), False otherwise.
    """
    print(f"[*] Attempting to disable monitor mode on interface: {monitor_interface}")

    stop_result = _run_airmon_command(["stop", monitor_interface])

    if stop_result is None:  # Critical error running command
        print(f"[-] Failed to execute 'airmon-ng stop {monitor_interface}'.")
        return False

    output = (stop_result.stdout or "") + (stop_result.stderr or "")

    if stop_result.returncode == 0:
        print(f"[+] 'airmon-ng stop {monitor_interface}' executed successfully.")
        # Check output for confirmation like "removed" or "returned to managed mode"
        if "removed" in output.lower() or "managed mode" in output.lower():
            print(f"[+] Monitor mode disabled on '{monitor_interface}'.")
        else:
            print(f"[?] Command successful, but specific confirmation message not found. Output: {output.strip()}")
        return True
    else:
        print(f"[-] 'airmon-ng stop {monitor_interface}' failed with exit code {stop_result.returncode}.")
        # Check if it failed because the interface was not in monitor mode or doesn't exist
        if "No such device" in output or "not in monitor mode" in output:
            print(f"    Reason: Interface '{monitor_interface}' not found or was not in monitor mode.")
            return True  # Treat as success if the goal is "not in monitor mode"
        if output.strip(): print(f"    Output: {output.strip()}")
        return False


# --- Main block for direct testing ---
if __name__ == "__main__":
    # Example Usage:
    # Run as: sudo python3 modules/interface_monitor.py <your_wireless_interface_like_wlan0>

    if len(sys.argv) < 2:
        print("Usage: python3 interface_monitor.py <wireless_interface_name>")
        print("Example: python3 interface_monitor.py wlan0")
        sys.exit(1)

    base_interface = sys.argv[1]
    print(f"--- Testing Monitor Mode for interface: {base_interface} ---")

    # Test enabling monitor mode
    print("\n[TEST] Enabling monitor mode...")
    monitor_iface = enable_monitor(base_interface, kill_conflicting_processes=True)
    if monitor_iface:
        print(f"[PASS] Monitor mode enabled. Monitor interface active: {monitor_iface}")

        # Test disabling monitor mode
        print(f"\n[TEST] Disabling monitor mode on {monitor_iface}...")
        if disable_monitor(monitor_iface):
            print(f"[PASS] Monitor mode disabled for {monitor_iface}.")
        else:
            print(f"[FAIL] Failed to disable monitor mode for {monitor_iface}.")
            print(f"       You might need to manually run: sudo airmon-ng stop {monitor_iface}")
            print(
                f"       And then ensure your network manager takes control: sudo systemctl restart NetworkManager (or similar)")
    else:
        print(f"[FAIL] Failed to enable monitor mode on {base_interface}.")
        print(f"       Ensure '{base_interface}' is a valid wireless interface and supports monitor mode.")
        print(f"       Try running 'sudo airmon-ng check' to see potential issues.")

    print("\n--- Testing with a non-existent interface (expect failure) ---")
    non_existent_iface = "fakewlan99thatdoesnotexist"
    print(f"\n[TEST] Enabling monitor mode on non-existent interface: {non_existent_iface}...")
    res_enable_fake = enable_monitor(non_existent_iface)
    if not res_enable_fake:
        print(f"[PASS] Correctly failed to enable monitor mode on {non_existent_iface}.")
    else:
        print(
            f"[FAIL] Unexpectedly 'succeeded' enabling monitor mode on {non_existent_iface} (monitor: {res_enable_fake}).")
        if res_enable_fake: disable_monitor(res_enable_fake)  # Attempt cleanup

    print(f"\n[TEST] Disabling monitor mode on non-existent interface: {non_existent_iface}mon...")
    res_disable_fake = disable_monitor(non_existent_iface + "mon")
    if res_disable_fake:  # It should report success if interface not found / not in monitor mode
        print(f"[PASS] Correctly handled attempt to disable monitor mode on non-existent/non-monitor interface.")
    else:  # This would be unusual unless _run_airmon_command itself had a critical failure
        print(f"[FAIL] Unexpected failure disabling monitor mode on non-existent interface.")

    print("\n--- Interface Monitor tests completed ---")