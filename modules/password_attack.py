# modules/password_attack.py

import subprocess
import os
import sys
import shutil
import re
import argparse
import time

# --- Configuration ---
CRUNCH_COMMAND = "crunch"
HYDRA_COMMAND = "hydra"
SUDO_COMMAND = "sudo"  # Hydra might not need sudo, crunch usually doesn't.
# ---------------------

# Global list for process management (if needed, though hydra is often blocking)
running_processes = []


def _is_tool_installed(name):
    """Checks if a command-line tool is installed and in PATH."""
    if shutil.which(name) is None:
        print(f"[!] Error: '{name}' command not found. Please install it.")
        return False
    return True


def generate_wordlist_crunch(output_file, min_len, max_len, charset=None, pattern=None, use_sudo=False):
    """
    Generates a wordlist using crunch.

    :param output_file: Path to save the generated wordlist.
    :param min_len: Minimum length of passwords.
    :param max_len: Maximum length of passwords.
    :param charset: (Optional) Character set to use (e.g., "abcdefghijklmnopqrstuvwxyz0123456789").
                    If None and pattern is None, crunch uses its default.
    :param pattern: (Optional) Crunch pattern (e.g., "@@pass%%"). Overrides charset if specific.
    :param use_sudo: Whether to use sudo for crunch (rarely needed).
    :return: True if successful, False otherwise.
    """
    print(f"[*] Generating wordlist using crunch: {output_file}")
    print(f"    Min length: {min_len}, Max length: {max_len}")

    if not _is_tool_installed(CRUNCH_COMMAND): return False
    if use_sudo and os.geteuid() != 0 and not _is_tool_installed(SUDO_COMMAND): return False

    cmd = []
    if use_sudo and os.geteuid() != 0: cmd.append(SUDO_COMMAND)
    cmd.append(CRUNCH_COMMAND)
    cmd.extend([str(min_len), str(max_len)])

    if charset:
        cmd.extend(["-f", "/usr/share/crunch/charset.lst", charset])  # Common path, or let user specify full path
        # Or simply: cmd.append(charset) if charset is a simple string like "abc"
        print(f"    Charset: {charset}")

    if pattern:
        cmd.extend(["-t", pattern])
        print(f"    Pattern: {pattern}")
    elif not charset:  # if no pattern and no charset, crunch uses its default lowercase alpha
        print("    Using crunch default charset (lowercase alpha).")

    cmd.extend(["-o", output_file])

    print(f"[*] Executing: {' '.join(cmd)}")
    print("[*] Crunch can take a very long time and generate huge files. Monitor disk space.")
    try:
        # Crunch can be very long-running. Popen allows for potential future interruption.
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        running_processes.append(process)  # Track it

        # Stream output if desired, or just wait
        stdout, stderr = process.communicate()  # This will block until crunch finishes
        return_code = process.returncode
        running_processes.remove(process)

        if return_code == 0:
            print(f"[+] Wordlist successfully generated: {output_file}")
            # Check file size as a basic success metric
            if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                return True
            elif os.path.exists(output_file):
                print(f"[-] Warning: Wordlist file '{output_file}' was created but is empty.")
                return False  # Or True depending on strictness
            else:
                print(f"[-] Error: Wordlist file '{output_file}' was not created by crunch.")
                return False
        else:
            print(f"[-] Crunch failed with exit code {return_code}.")
            if stdout: print(f"    Stdout: {stdout.strip()}")
            if stderr: print(f"    Stderr: {stderr.strip()}")
            return False
    except KeyboardInterrupt:
        print("\n[!] Wordlist generation interrupted by user.")
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except:
                process.kill()
            if process in running_processes: running_processes.remove(process)
        return False
    except Exception as e:
        print(f"[-] An unexpected error occurred during wordlist generation: {e}")
        return False


def run_hydra_attack(target, service,
                     username=None, user_list_file=None,
                     password=None, password_list_file=None,
                     port=None, threads=16, timeout=5, attempts_per_host=0,
                     custom_options=None, use_sudo=False):
    """
    Runs a Hydra attack (brute-force or password spray).

    :param target: Target IP address or hostname.
    :param service: Service to attack (e.g., "ssh", "http-get", "ftp", "smb").
    :param username: Single username to test.
    :param user_list_file: Path to a file containing a list of usernames.
    :param password: Single password to test (for password spray).
    :param password_list_file: Path to a file containing a list of passwords.
    :param port: (Optional) Specify a non-standard port for the service.
    :param threads: Number of parallel tasks for Hydra (default: 16).
    :param timeout: Timeout in seconds for each connection attempt (default: 5).
    :param attempts_per_host: Stop after this many attempts per host (0 for no limit, good for spraying).
    :param custom_options: (Optional) List of additional Hydra command-line options.
    :param use_sudo: Whether to use sudo for Hydra (rarely needed).
    :return: A list of tuples [(username, password)] for found credentials, or an empty list.
    """
    found_credentials = []
    attack_type = "unknown"

    if not _is_tool_installed(HYDRA_COMMAND): return found_credentials
    if use_sudo and os.geteuid() != 0 and not _is_tool_installed(SUDO_COMMAND): return found_credentials

    cmd = []
    if use_sudo and os.geteuid() != 0: cmd.append(SUDO_COMMAND)
    cmd.append(HYDRA_COMMAND)

    # User part
    if username:
        cmd.extend(["-l", username])
        attack_type = "single_user_bruteforce" if password_list_file else "specific_credential_check"
    elif user_list_file:
        if not os.path.isfile(user_list_file):
            print(f"[!] User list file not found: {user_list_file}")
            return found_credentials
        cmd.extend(["-L", user_list_file])
        attack_type = "multi_user_bruteforce" if password_list_file else "password_spray_multi_user"
    else:
        print("[!] Error: Either a username (-l) or user list (-L) must be provided for Hydra.")
        return found_credentials

    # Password part
    if password:
        cmd.extend(["-p", password])
        if user_list_file:
            attack_type = "password_spray_multi_user"
        elif username:
            attack_type = "specific_credential_check" if not password_list_file else "single_user_bruteforce"  # Ambiguous
    elif password_list_file:
        if not os.path.isfile(password_list_file):
            print(f"[!] Password list file not found: {password_list_file}")
            return found_credentials
        cmd.extend(["-P", password_list_file])
        # attack_type already set by user part logic
    else:
        print("[!] Error: Either a password (-p) or password list (-P) must be provided for Hydra.")
        return found_credentials

    if port:
        cmd.extend(["-s", str(port)])

    cmd.extend(["-t", str(threads)])  # Number of tasks
    cmd.extend(["-w", str(timeout)])  # Wait time (timeout)

    if attempts_per_host > 0:  # Good for password spraying to avoid lockout
        # Hydra uses -x min:max:charset for password generation, not for attempts limit.
        # For attempt limits, it's usually a feature of the specific module or needs external logic.
        # Hydra's main attempt limit is usually per user/pass combo.
        # The closest hydra has is -u (loop around users, not passwords)
        # and some protocols have specific options.
        # For general "stop after N attempts against a host", you might need to script hydra or use other tools.
        # However, for password spraying, you typically give ONE password and a LIST of users.
        # If you mean "exit after finding X successes", use -x option.
        # If you mean "try each password N times", that's not a direct hydra flag.
        # Let's assume this means `-F` (stop after first pair found).
        # If you want to stop after N attempts to avoid lockout, that's complex.
        # The description "attempts_per_host" is a bit vague for Hydra.
        # Let's interpret it as `-F` if it's 1, otherwise it's not directly supported this way.
        if attempts_per_host == 1:  # Stop on first success
            cmd.append("-F")
            print("[*] Hydra will stop after the first valid credential pair is found (-F).")
        else:
            print(
                f"[*] Note: 'attempts_per_host' ({attempts_per_host}) > 1 for overall attack is not a direct Hydra flag. Consider -F for stopping on first success.")

    if custom_options and isinstance(custom_options, list):
        cmd.extend(custom_options)

    cmd.append(target)
    cmd.append(service)

    print(f"[*] Starting Hydra {attack_type} attack on {target}:{service or 'default_port'}")
    print(f"    Command: {' '.join(cmd)}")
    print("[*] Hydra may take a long time. Output will be streamed.")

    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
        running_processes.append(process)

        # Regex to find successful logins from Hydra's output
        # Example: "[ssh] host: 192.168.1.10 login: admin password: password123"
        # Example: "192.168.1.100 ssh: login admin password password" (older hydra)
        # Example: "[SUCCESS] Target: 192.168.1.1, Service: ssh, Login: root, Pass: toor"
        # A common pattern is "host: <host> login: <login> password: <password>"
        # Or "[<attempts>] <service> host: <target> port: <port> login: <user> pass: <pass>"
        # Hydra's output format can vary. A more robust one:
        # "login: <user> password: <password>" after a host line.
        # Let's try a general one: looking for "login: " and "password: " on the same or subsequent lines
        # related to a success message.

        # A simple line-based success indicator:
        # "[80][http-get] host: 10.0.0.76 login: admin password: password"

        # Regex patterns to try:
        # 1. Standard format: "host: target login: user password: pass"
        pattern1 = re.compile(r"host:\s*[\w\.\-]+\s*login:\s*(\S+)\s*password:\s*(\S+)", re.IGNORECASE)
        # 2. Format with [attempts] prefix:
        pattern2 = re.compile(r"login:\s*(\S+)\s*pass:\s*(\S+)",
                              re.IGNORECASE)  # Simpler if host info is on another line

        current_stdout_lines = []

        for line in iter(process.stdout.readline, ''):
            sys.stdout.write(f"[Hydra] {line}")  # Stream Hydra's output
            sys.stdout.flush()
            current_stdout_lines.append(line.strip())
            if len(current_stdout_lines) > 5:  # Keep a small buffer for multi-line context
                current_stdout_lines.pop(0)

            # Check for success patterns
            # Pattern 1 (more specific)
            match = pattern1.search(line)
            if match:
                user, pw = match.group(1), match.group(2)
                if (user, pw) not in found_credentials:
                    print(f"\033[92m[SUCCESS] Credential found by Hydra: User='{user}', Password='{pw}'\033[0m")
                    found_credentials.append((user, pw))
                    # If -F was used, Hydra might exit soon. If not, we continue.
            else:
                # Pattern 2 (more general, might need context from previous lines if host info is separate)
                # This is less reliable without context of which host.
                # For now, stick to pattern1 or a clear "SUCCESS" message if Hydra has one.
                # Some Hydra versions print a summary line at the end for successes.
                pass

        process.stdout.close()
        stderr_output = process.stderr.read()
        process.stderr.close()
        return_code = process.wait()
        running_processes.remove(process)

        if return_code != 0 and not found_credentials:  # Hydra might exit non-zero even on success sometimes.
            print(f"[-] Hydra process exited with code {return_code}.")
            if stderr_output:
                print(f"    Stderr: {stderr_output.strip()}")

        if not found_credentials:
            print("[-] No credentials found by Hydra with the provided lists/options.")

        return found_credentials

    except KeyboardInterrupt:
        print("\n[!] Hydra attack interrupted by user.")
        if 'process' in locals() and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except:
                process.kill()
            if process in running_processes: running_processes.remove(process)
        return found_credentials  # Return any found so far
    except Exception as e:
        print(f"[-] An unexpected error occurred during Hydra attack: {e}")
        return found_credentials  # Return any found so far


# --- Main execution for demonstration ---
def main():
    parser = argparse.ArgumentParser(description="Password attack utilities using Crunch and Hydra.")
    subparsers = parser.add_subparsers(dest="command", title="Available commands", required=True)

    # Crunch subparser
    crunch_parser = subparsers.add_parser("crunch", help="Generate wordlists with crunch.")
    crunch_parser.add_argument("output_file", help="Path to save the generated wordlist.")
    crunch_parser.add_argument("min_len", type=int, help="Minimum password length.")
    crunch_parser.add_argument("max_len", type=int, help="Maximum password length.")
    crunch_parser.add_argument("-c", "--charset",
                               help="Character set string (e.g., 'abcdef0123') or name from charset.lst.")
    crunch_parser.add_argument("-p", "--pattern", help="Crunch pattern (e.g., '@@pass%%').")

    # Hydra subparser
    hydra_parser = subparsers.add_parser("hydra", help="Perform brute-force/password spray with Hydra.")
    hydra_parser.add_argument("target", help="Target IP address or hostname.")
    hydra_parser.add_argument("service", help="Service to attack (e.g., ssh, ftp, http-get).")

    user_group = hydra_parser.add_mutually_exclusive_group(required=True)
    user_group.add_argument("-l", "--username", help="Single username.")
    user_group.add_argument("-L", "--userlist", help="Path to username list file.")

    pass_group = hydra_parser.add_mutually_exclusive_group(required=True)
    pass_group.add_argument("-p", "--password", help="Single password (for spraying or specific check).")
    pass_group.add_argument("-P", "--passlist", help="Path to password list file.")

    hydra_parser.add_argument("-s", "--port", type=int, help="Optional non-standard port for the service.")
    hydra_parser.add_argument("-t", "--threads", type=int, default=16,
                              help="Number of parallel tasks for Hydra (default: 16).")
    hydra_parser.add_argument("-w", "--timeout", type=int, default=5,
                              help="Connection timeout in seconds (default: 5).")
    hydra_parser.add_argument("--opts", nargs='*', help="Additional raw options for Hydra (e.g., --opts '-V' '-d').")

    args = parser.parse_args()

    print("=======================================================")
    print("                Password Attack Utility                ")
    print("=======================================================")
    print("Disclaimer: Educational purposes ONLY. Unauthorized access is illegal.")
    print("=======================================================\n")

    # Global signal handler for graceful shutdown
    def signal_handler(sig, frame):
        print(f"\n[!] Signal {sig} received. Shutting down running processes...")
        # Stop any tracked background processes (mainly for crunch if it was daemonized)
        for p in list(running_processes):  # Iterate over a copy
            if p.poll() is None:
                print(f"[*] Terminating PID {p.pid}...")
                p.terminate()
                try:
                    p.wait(timeout=2)
                except:
                    p.kill()
            if p in running_processes: running_processes.remove(p)
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.command == "crunch":
        success = generate_wordlist_crunch(
            args.output_file, args.min_len, args.max_len,
            charset=args.charset, pattern=args.pattern
        )
        if success:
            print(f"[+] Crunch command finished. Wordlist: {args.output_file}")
        else:
            print("[-] Crunch command failed.")

    elif args.command == "hydra":
        found = run_hydra_attack(
            args.target, args.service,
            username=args.username, user_list_file=args.userlist,
            password=args.password, password_list_file=args.passlist,
            port=args.port, threads=args.threads, timeout=args.timeout,
            custom_options=args.opts
        )
        if found:
            print("\n[+] Hydra attack finished. Found credentials:")
            for user, pw in found:
                print(f"    Login: {user}, Password: {pw}")
        else:
            print("\n[-] Hydra attack finished. No credentials found or an error occurred.")

    print("\n[*] Script finished.")


if __name__ == "__main__":
    main()