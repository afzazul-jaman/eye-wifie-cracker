# modules/wifiphisher_attack.py

import subprocess
import os
import sys
import shutil
import argparse
import signal
import time

# --- Configuration ---
WIFIPHISHER_COMMAND = "wifiphisher"
SUDO_COMMAND = "sudo"
# ---------------------

# Store Popen object for potential cleanup
wifiphisher_process = None


def _is_tool_installed(name):
    """Checks if a command-line tool is installed and in PATH."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def _stop_wifiphisher_process():
    """Attempts to stop the wifiphisher process if it's running."""
    global wifiphisher_process
    if wifiphisher_process and wifiphisher_process.poll() is None:
        print(f"[*] Attempting to stop Wifiphisher (PID: {wifiphisher_process.pid})...")
        try:
            # Wifiphisher usually handles Ctrl+C gracefully.
            # Sending SIGINT to the sudo process should propagate.
            if os.geteuid() == 0 or wifiphisher_process.args[0] != SUDO_COMMAND:
                wifiphisher_process.send_signal(signal.SIGINT)
            else:
                os.kill(wifiphisher_process.pid, signal.SIGINT)

            wifiphisher_process.wait(timeout=10)  # Give it time to clean up
            print("[+] Wifiphisher stopped.")
        except subprocess.TimeoutExpired:
            print("[!] Wifiphisher did not respond to SIGINT, sending SIGTERM/SIGKILL.")
            wifiphisher_process.terminate()
            try:
                wifiphisher_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                wifiphisher_process.kill()
                wifiphisher_process.wait()
            print("[+] Wifiphisher force-stopped.")
        except Exception as e:
            print(f"[!] Error stopping Wifiphisher: {e}. Attempting force kill.")
            wifiphisher_process.kill()
            wifiphisher_process.wait()
        wifiphisher_process = None
        return True
    return False


def start_wifiphisher_attack(
        phishing_interface,
        essid=None,
        phishing_scenario=None,
        internet_interface=None,  # For NAT mode
        deauth_interface=None,  # For deauth attacks, often same as phishing_interface
        no_extensions=False,
        additional_options=None
):
    """
    Starts a phishing attack using Wifiphisher.

    :param phishing_interface: Wireless interface for the fake AP (e.g., wlan0).
                               Wifiphisher will try to put it in AP mode.
    :param essid: (Optional) ESSID for the fake AP. If None, Wifiphisher might prompt or use a default.
    :param phishing_scenario: (Optional) Name of the phishing scenario to run (e.g., "firmware_upgrade").
    :param internet_interface: (Optional) Interface providing internet for NAT mode (e.g., eth0).
    :param deauth_interface: (Optional) Interface for deauthentication attacks. If None, may use phishing_interface.
    :param no_extensions: (Optional) If True, disables loading of extensions (--noextensions).
    :param additional_options: (Optional) List of other raw command-line options for Wifiphisher.
    :return: Popen object for the Wifiphisher process if started, None otherwise.
    """
    global wifiphisher_process
    print(f"[*] Preparing to start Wifiphisher attack on interface {phishing_interface}...")

    if not _is_tool_installed(WIFIPHISHER_COMMAND): return None
    if os.geteuid() != 0 and not _is_tool_installed(SUDO_COMMAND): return None  # Wifiphisher needs root

    cmd = [WIFIPHISHER_COMMAND]

    # Core interface option (Wifiphisher has renamed flags over time)
    # Check Wifiphisher --help for latest. Common is -i or --interface
    # Some versions used -aI for AP interface, -eI for internet interface
    # Modern versions are more flexible with just --interface and --internet-interface
    if phishing_interface:
        # Wifiphisher uses --interface or -i for the AP interface.
        # Or sometimes -aI or --ap-interface
        cmd.extend(["--interface", phishing_interface])  # More common now
        # cmd.extend(["-i", phishing_interface]) is also seen.

    if deauth_interface:
        # For deauth, it might use a separate interface or the same one.
        # Wifiphisher manages deauth internally based on scenario typically.
        # Some flags like --deauth-essid <ESSID> exist.
        # Or --jamming-interface <iface>
        cmd.extend(["--jamming-interface", deauth_interface])  # Example, check current Wifiphisher docs

    if essid:
        cmd.extend(["-e", essid])  # or --essid

    if phishing_scenario:
        cmd.extend(["-p", phishing_scenario])  # or --phishingscenario

    if internet_interface:
        cmd.extend(["--internet-interface", internet_interface])  # or -eI
        print(f"[*] NAT mode will be attempted using internet from: {internet_interface}")
    else:
        print("[*] Running without an internet interface (no NAT forwarding by default).")

    if no_extensions:
        cmd.append("--noextensions")

    if additional_options and isinstance(additional_options, list):
        cmd.extend(additional_options)

    # Example from original snippet `--target phishing_target --ap-fake`
    # `--target` is not a standard wifiphisher flag. It might be a custom scenario name or confused.
    # `--ap-fake` also not standard. Wifiphisher *is* a fake AP tool.
    # Perhaps the user meant specific scenario options or was thinking of another tool.
    # We will omit these unless they are passed via `additional_options`.
    # For instance, to target a specific AP for deauth, you might use:
    # --deauth-essid "TargetAPName" or related flags.

    # Prepend sudo if not root
    final_cmd = [SUDO_COMMAND] + cmd if os.geteuid() != 0 else cmd

    print(f"[*] Executing: {' '.join(final_cmd)}")
    print("[+] Wifiphisher will now take over this terminal window.")
    print("[+] Follow the on-screen instructions from Wifiphisher.")
    print("[+] To stop Wifiphisher, press Ctrl+C in THIS window (or as instructed by Wifiphisher).")

    try:
        # Wifiphisher is highly interactive, so run it in the current terminal context.
        # We don't capture stdout/stderr typically, as the user interacts directly.
        wifiphisher_process = subprocess.Popen(final_cmd)
        # The script will now block here if we call .wait().
        # If we don't call .wait(), the Python script might exit while wifiphisher runs,
        # or it can continue to do other things. For this wrapper, waiting is usually desired.
        # Return the process so the caller can decide to wait or manage it.
        return wifiphisher_process
    except FileNotFoundError:
        print(f"[!] Error: Command '{final_cmd[0]}' not found.")
        return None
    except Exception as e:
        print(f"[!] An unexpected error occurred while starting Wifiphisher: {e}")
        return None


# --- Main execution for demonstration ---
def main():
    parser = argparse.ArgumentParser(description="Wifiphisher Attack Launcher.")
    parser.add_argument("phishing_interface",
                        help="Wireless interface for the Evil AP (e.g., wlan0). Wifiphisher will attempt to manage its mode.")
    parser.add_argument("-e", "--essid", help="ESSID for the fake AP.")
    parser.add_argument("-p", "--scenario",
                        help="Name of the phishing scenario (e.g., 'firmware_upgrade', 'oauth_login').")
    parser.add_argument("-iI", "--internet-interface", help="Interface providing internet for NAT (e.g., eth0).")
    parser.add_argument("-jI", "--jamming-interface",
                        help="Interface for deauth/jamming attacks (can be same as phishing_interface).")
    parser.add_argument("--no-extensions", action="store_true", help="Disable Wifiphisher extensions (--noextensions).")
    parser.add_argument("--opts", nargs='*',
                        help="Additional raw command-line options for Wifiphisher (e.g., --opts '--log' 'phisher.log').")

    args = parser.parse_args()

    print("=======================================================")
    print("                Wifiphisher Attack Launcher            ")
    print("=======================================================")
    print("Disclaimer: Educational purposes ONLY. Unauthorized access is illegal.")
    print("This script launches Wifiphisher, which is a powerful tool.")
    print("Ensure you have permission and understand its operation.")
    print("=======================================================\n")

    if os.geteuid() != 0:
        print("[!] Wifiphisher requires root privileges to run.")
        print("    This script will attempt to use 'sudo'. Ensure your user has sudo rights.")
        # No sys.exit here, let the sudo call fail if necessary.

    # Setup signal handler for graceful shutdown
    def signal_handler_main(sig, frame):
        print(f"\n[!] Signal {sig} received by launcher script. Attempting to stop Wifiphisher...")
        _stop_wifiphisher_process()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler_main)
    signal.signal(signal.SIGTERM, signal_handler_main)

    process = start_wifiphisher_attack(
        phishing_interface=args.phishing_interface,
        essid=args.essid,
        phishing_scenario=args.scenario,
        internet_interface=args.internet_interface,
        deauth_interface=args.jamming_interface,
        no_extensions=args.no_extensions,
        additional_options=args.opts
    )

    if process:
        print(f"[+] Wifiphisher launched with PID: {process.pid}. Waiting for it to complete...")
        try:
            # Wait for Wifiphisher to exit. This makes the script block.
            # Wifiphisher runs until the user quits it (e.g., Ctrl+C in its interactive session).
            exit_code = process.wait()
            print(f"[+] Wifiphisher exited with code: {exit_code}")
        except KeyboardInterrupt:  # If this script gets Ctrl+C while waiting
            print("\n[!] Launcher script interrupted. Relaying signal to Wifiphisher...")
            _stop_wifiphisher_process()  # Will be handled by signal_handler_main too, but good to have
        except Exception as e:
            print(f"[!] Error while waiting for Wifiphisher: {e}")
            _stop_wifiphisher_process()  # Attempt cleanup
        finally:
            # Ensure the global process variable is cleared if Popen object becomes invalid
            global wifiphisher_process
            wifiphisher_process = None
    else:
        print("[-] Failed to start Wifiphisher.")

    print("\n[*] Wifiphisher launcher script finished.")


if __name__ == "__main__":
    main()