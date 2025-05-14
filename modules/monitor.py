# modules/executor.py

import subprocess
import os
import shutil  # For shutil.which

SUDO_COMMAND = "sudo"  # Define it here or import from a common config


def _is_tool_installed(name):
    """Internal helper to check if a tool is installed."""
    return shutil.which(name) is not None


def run_command(command_list, use_sudo=False, capture_output=True, check=False, text=True, timeout=None, cwd=None,
                env=None):
    """
    Executes a system command.

    :param command_list: A list of strings representing the command and its arguments
                         (e.g., ["ls", "-l", "/tmp"]).
    :param use_sudo: If True and the script is not run as root, prepends "sudo" to the command.
    :param capture_output: If True, stdout and stderr will be captured.
    :param check: If True, raises CalledProcessError if the command returns a non-zero exit code.
    :param text: If True, decodes stdout and stderr as text (universal_newlines=True).
    :param timeout: Optional command timeout in seconds.
    :param cwd: Optional current working directory for the command.
    :param env: Optional dictionary of environment variables for the command.
    :return: subprocess.CompletedProcess object.
             Access result.stdout, result.stderr, result.returncode.
             Returns None if a preliminary check (like sudo not found) fails.
    """
    if not isinstance(command_list, list):
        print("[!] Error: 'command_list' must be a list of strings.")
        # Optionally raise TypeError or return a specific error indicator
        return None  # Or a CompletedProcess object with a custom error code/message

    final_command = list(command_list)  # Make a copy to modify

    if use_sudo and os.geteuid() != 0:  # Only add sudo if not root and use_sudo is True
        if not _is_tool_installed(SUDO_COMMAND):
            print(f"[!] Error: '{SUDO_COMMAND}' command not found, but 'use_sudo' is True.")
            # Create a mock CompletedProcess for consistent return type on pre-check failure
            return subprocess.CompletedProcess(args=final_command, returncode=-1,
                                               stdout=None, stderr=f"'{SUDO_COMMAND}' not found.")
        final_command.insert(0, SUDO_COMMAND)

    cmd_str_for_log = ' '.join(final_command)  # For logging purposes
    print(f"[*] Executing command: {cmd_str_for_log}")

    try:
        result = subprocess.run(
            final_command,
            capture_output=capture_output,
            check=check,  # If True, will raise CalledProcessError on non-zero exit
            text=text,
            timeout=timeout,
            cwd=cwd,
            env=env
        )
        if result.returncode != 0 and not check:  # If check is False, print warning for errors
            print(f"[!] Warning: Command exited with code {result.returncode}.")
            if capture_output:
                if result.stdout: print(f"    Stdout: {result.stdout.strip()}")
                if result.stderr: print(f"    Stderr: {result.stderr.strip()}")
        return result

    except subprocess.CalledProcessError as e:
        # This block is only reached if check=True and the command failed.
        # The 'e' object is a CompletedProcess instance itself.
        print(f"[-] Command failed with exit code {e.returncode}: {cmd_str_for_log}")
        if capture_output:  # Even if check=True, e.stdout/stderr will be populated if captured
            if e.stdout: print(f"    Stdout: {e.stdout.strip()}")
            if e.stderr: print(f"    Stderr: {e.stderr.strip()}")
        return e  # Return the exception object which is also a CompletedProcess
    except FileNotFoundError:
        # This means the executable itself (e.g., final_command[0]) was not found.
        print(f"[!] Error: Executable '{final_command[0]}' not found.")
        return subprocess.CompletedProcess(args=final_command, returncode=-2,  # Custom error code
                                           stdout=None, stderr=f"Executable '{final_command[0]}' not found.")
    except subprocess.TimeoutExpired as e:
        print(f"[!] Command timed out after {timeout} seconds: {cmd_str_for_log}")
        return subprocess.CompletedProcess(args=final_command, returncode=-3,  # Custom error code
                                           stdout=e.stdout, stderr=e.stderr)  # stdout/stderr might have partial data
    except Exception as e:
        print(f"[!] An unexpected error occurred while running command '{cmd_str_for_log}': {e}")
        return subprocess.CompletedProcess(args=final_command, returncode=-4,  # Custom error code
                                           stdout=None, stderr=str(e))


if __name__ == "__main__":
    print("\n--- Testing executor.run_command ---")

    # 1. Simple command, capture output, no check
    print("\nTest 1: ls -l /tmp (capture, no check)")
    result1 = run_command(["ls", "-l", "/tmp"], capture_output=True, check=False)
    if result1 and result1.returncode == 0:
        print(f"LS Output (first 100 chars): {result1.stdout[:100].strip()}...")
    elif result1:
        print(f"LS command failed with code {result1.returncode}")

    # 2. Command that needs sudo (assuming user has sudo rights for 'whoami')
    print("\nTest 2: sudo whoami (capture, no check)")
    result2 = run_command(["whoami"], use_sudo=True, capture_output=True, check=False)
    if result2 and result2.returncode == 0:
        print(f"Sudo Whoami Output: {result2.stdout.strip()}")
    elif result2:
        print(f"Sudo Whoami failed with code {result2.returncode}. Stderr: {result2.stderr.strip()}")

    # 3. Command that will fail, with check=True (expect CalledProcessError handling)
    print("\nTest 3: ls /nonexistent_path (capture, check=True)")
    result3 = run_command(["ls", "/nonexistent_path"], capture_output=True, check=True)
    if result3 and result3.returncode != 0:  # If check=True and error, result3 is the CalledProcessError
        print(f"LS Nonexistent failed as expected. Return code: {result3.returncode}")
        print(f"Stderr: {result3.stderr.strip()}")
    elif result3:  # Should not happen if check=True caused an exception caught by the function
        print("LS Nonexistent succeeded unexpectedly.")

    # 4. Command that will fail, with check=False
    print("\nTest 4: ls /nonexistent_path (capture, check=False)")
    result4 = run_command(["ls", "/nonexistent_path"], capture_output=True, check=False)
    if result4 and result4.returncode != 0:
        print(f"LS Nonexistent failed as expected. Return code: {result4.returncode}")
        print(f"Stderr: {result4.stderr.strip()}")
    elif result4:
        print("LS Nonexistent succeeded unexpectedly.")

    # 5. Non-existent command
    print("\nTest 5: non_existent_command_123")
    result5 = run_command(["non_existent_command_123"], capture_output=True, check=False)
    if result5 and result5.returncode < 0:  # Using custom negative return codes
        print(f"Non-existent command failed as expected. Stderr: {result5.stderr.strip()}")

    # 6. Interactive command (or long running), no capture, no check
    # This will print directly to console.
    # print("\nTest 6: ping -c 1 google.com (no capture, no check)")
    # result6 = run_command(["ping", "-c", "1", "google.com"], capture_output=False, check=False, timeout=5)
    # if result6:
    # print(f"Ping command finished with code: {result6.returncode}")

    print("\n--- Executor tests finished ---")