# main.py
import sys
import os
import subprocess  # Keep for direct calls if any module doesn't encapsulate fully
import time  # For timestamp in default PMKID pcap name
import shutil  # For shutil.which in pyrit_brute_force
import re  # For re.search in pyrit_brute_force

# --- START: sys.path modification ---
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
    print(f"[*] Added project root to sys.path: {project_root}")
else:
    print(f"[*] Project root already in sys.path: {project_root}")
# --- END: sys.path modification ---

from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton,
                             QLabel, QScrollArea, QFrame, QGroupBox, QTextEdit,
                             QInputDialog, QMessageBox)
from PyQt5.QtCore import QThread, pyqtSignal, QObject

# --- Module Imports (Ensure these match your solved module filenames) ---
try:
    import modules.interface_monitor as interface_monitor
    import modules.handshake as handshake
    import modules.pmkid as pmkid_module
    import modules.evil_twin as evil_twin
    import modules.wps_attack as wps_attack
    import modules.password_attack as password_attack
    import modules.scanning_recon as scanning_recon
    import modules.deauth_attack as deauth_attack
    import modules.wifiphisher_attack as wifiphisher_attack
    import modules.automated_wifi_attack as automated_attack
except ImportError as e:
    print(f"CRITICAL Error importing modules: {e}.")
    print("Please ensure the following:")
    print(f"1. Your project root directory ('{project_root}') is correct and contains the 'modules' directory.")
    print(
        "2. The 'modules' directory contains all required .py files (e.g., interface_monitor.py, handshake.py, etc.).")
    print("3. The 'modules' directory contains an empty '__init__.py' file to make it a package.")
    print(f"4. Current sys.path: {sys.path}")
    sys.exit(1)


# --- For redirecting stdout/stderr to QTextEdit ---
class QTextEditLogger(QObject):
    messageWritten = pyqtSignal(str)

    def write(self, msg):
        self.messageWritten.emit(str(msg))

    def flush(self):
        pass


# --- Worker thread for long-running tasks ---
class Worker(QThread):
    finished = pyqtSignal()
    error = pyqtSignal(str)
    result = pyqtSignal(object)

    def __init__(self, function, *args, **kwargs):
        super().__init__()
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.active_popen = None

    def run(self):
        try:
            res = self.function(*self.args, **self.kwargs)
            self.result.emit(res)
        except Exception as e:
            self.error.emit(str(e))
        finally:
            self.finished.emit()


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.evil_twin_instance = None
        self.active_workers = []
        self.initUI()
        self.init_logging()

    def init_logging(self):
        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setLineWrapMode(QTextEdit.WidgetWidth)
        self.log_output.setFixedHeight(200)
        self.main_layout.insertWidget(0, self.log_output)

        self.stdout_logger = QTextEditLogger()
        self.stdout_logger.messageWritten.connect(self.log_output.insertPlainText)
        sys.stdout = self.stdout_logger

        self.stderr_logger = QTextEditLogger()
        self.stderr_logger.messageWritten.connect(self.log_output.insertPlainText)
        sys.stderr = self.stderr_logger

        print("GUI Logger Initialized.\n")

    def initUI(self):
        self.setWindowTitle("WiFi Security Testing Tool Suite")
        self.setGeometry(100, 100, 650, 850)

        self.main_layout = QVBoxLayout()

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout(scroll_content)

        scroll_layout.addWidget(self.create_monitor_mode_section())
        scroll_layout.addWidget(self.create_scanning_recon_section())
        scroll_layout.addWidget(self.create_handshake_section())
        scroll_layout.addWidget(self.create_pmkid_section())
        scroll_layout.addWidget(self.create_deauth_section())
        scroll_layout.addWidget(self.create_evil_twin_section())
        scroll_layout.addWidget(self.create_wps_section())
        scroll_layout.addWidget(self.create_password_section())
        scroll_layout.addWidget(self.create_automated_attacks_section())

        stop_all_btn = QPushButton("! EMERGENCY STOP ALL TRACKED ACTIONS !")
        stop_all_btn.setStyleSheet("background-color: #FF6347; color: white; font-weight: bold; padding: 5px;")
        stop_all_btn.clicked.connect(self.emergency_stop_all_actions)
        scroll_layout.addWidget(stop_all_btn)

        scroll_content.setLayout(scroll_layout)
        scroll.setWidget(scroll_content)
        self.main_layout.addWidget(scroll)

        self.setLayout(self.main_layout)

    def run_task_in_thread(self, function, *args, **kwargs):
        self.active_workers = [w for w in self.active_workers if w.isRunning()]
        worker = Worker(function, *args, **kwargs)
        worker.finished.connect(lambda w=worker: self._worker_finished(w))
        worker.error.connect(self._worker_error)
        worker.result.connect(self._worker_result)
        self.active_workers.append(worker)
        worker.start()
        print(f"[*] Task '{function.__name__}' starting in a new thread.")

    def _worker_finished(self, worker):
        print(f"[*] Task '{worker.function.__name__}' finished.")
        if worker in self.active_workers:
            self.active_workers.remove(worker)

    def _worker_error(self, error_message):
        full_error_message = f"[!!!] Thread Error: {error_message}"
        print(full_error_message)
        QMessageBox.critical(self, "Thread Error", error_message)

    def _worker_result(self, result):
        if result is not None and not (isinstance(result, (list, str, tuple)) and not result):
            result_str = str(result)
            if len(result_str) > 500:
                result_str = result_str[:500] + "..."
            print(f"[+] Task Result: {result_str}")

            if isinstance(result, list) and result:
                self.log_output.append("\n--- Task Results ---")
                for item in result:
                    self.log_output.append(f"  {str(item)}")
                self.log_output.append("--------------------\n")
            elif isinstance(result, str) and result:
                self.log_output.append(f"\nResult: {result}\n")

    # --- Section Creation Methods ---
    def create_monitor_mode_section(self):
        group = QGroupBox("Monitor Mode (airmon-ng)")
        layout = QVBoxLayout()
        default_iface = "wlan0"

        enable_btn = QPushButton(f"Enable Monitor Mode ({default_iface})")
        enable_btn.clicked.connect(lambda: self.run_task_in_thread(interface_monitor.enable_monitor, default_iface,
                                                                   kill_conflicting_processes=True))
        layout.addWidget(enable_btn)

        disable_btn = QPushButton(f"Disable Monitor Mode ({default_iface}mon)")
        disable_btn.clicked.connect(
            lambda: self.run_task_in_thread(interface_monitor.disable_monitor, f"{default_iface}mon"))
        layout.addWidget(disable_btn)
        group.setLayout(layout)
        return group

    def create_scanning_recon_section(self):
        group = QGroupBox("Scanning & Reconnaissance")
        layout = QVBoxLayout()
        default_mon_iface = "wlan0mon"

        scan_iwlist_btn = QPushButton(f"Scan (iwlist on {default_mon_iface})")
        scan_iwlist_btn.clicked.connect(
            lambda: self.run_task_in_thread(scanning_recon.scan_networks_iwlist, default_mon_iface))
        layout.addWidget(scan_iwlist_btn)

        scan_nmcli_btn = QPushButton("Scan (nmcli)")
        scan_nmcli_btn.clicked.connect(lambda: self.run_task_in_thread(scanning_recon.scan_networks_nmcli))
        layout.addWidget(scan_nmcli_btn)

        status_btn = QPushButton("Show Interface Status")
        status_btn.clicked.connect(
            lambda: self.run_task_in_thread(scanning_recon.get_interface_status, default_mon_iface))
        layout.addWidget(status_btn)

        wash_btn = QPushButton(f"Scan WPS (Wash on {default_mon_iface})")
        wash_btn.clicked.connect(
            lambda: self.run_task_in_thread(scanning_recon.scan_wps_networks_wash, default_mon_iface,
                                            timeout_seconds=30))
        layout.addWidget(wash_btn)

        kismet_btn = QPushButton(f"Start Kismet (Source: {default_mon_iface})")
        kismet_btn.clicked.connect(
            lambda: self.run_task_in_thread(scanning_recon.start_kismet_monitor, default_mon_iface))
        layout.addWidget(kismet_btn)

        stop_kismet_btn = QPushButton("Stop Kismet (if started by this app)")
        stop_kismet_btn.clicked.connect(
            lambda: self.run_task_in_thread(scanning_recon._stop_interactive_tool, "Kismet"))
        layout.addWidget(stop_kismet_btn)
        group.setLayout(layout)
        return group

    def create_handshake_section(self):
        group = QGroupBox("WPA/WPA2 Handshake Attacks")
        layout = QVBoxLayout()
        default_mon_iface = "wlan0mon"
        default_bssid = "AA:BB:CC:DD:EE:FF"
        default_channel = 6
        default_hs_prefix = "gui_handshake"
        default_cap_dir = handshake.CAPTURE_DIR_DEFAULT if hasattr(handshake,
                                                                   'CAPTURE_DIR_DEFAULT') else "/tmp/wifi_captures"
        default_hs_file_to_crack = os.path.join(default_cap_dir, f"{default_hs_prefix}-01.cap")
        default_wordlist = "/usr/share/wordlists/rockyou.txt"

        capture_btn = QPushButton(f"Capture Handshake (Target: {default_bssid})")
        capture_btn.clicked.connect(
            lambda: self.run_task_in_thread(handshake.capture_handshake, default_mon_iface, default_bssid,
                                            default_channel, default_hs_prefix, deauth_packets=5, timeout=60)
        )
        layout.addWidget(capture_btn)

        crack_btn = QPushButton(f"Crack Handshake (aircrack-ng)")
        crack_btn.clicked.connect(
            lambda: self.run_task_in_thread(handshake.crack_handshake_file, default_hs_file_to_crack, default_wordlist,
                                            default_bssid)
        )
        layout.addWidget(crack_btn)

        pyrit_btn = QPushButton("Crack Handshake (Pyrit)")
        pyrit_btn.clicked.connect(
            lambda: self.run_task_in_thread(self.pyrit_brute_force, default_hs_file_to_crack, default_wordlist))
        layout.addWidget(pyrit_btn)
        group.setLayout(layout)
        return group

    def create_pmkid_section(self):
        group = QGroupBox("WPA/WPA2 PMKID Attacks (hcxtools + Hashcat)")
        layout = QVBoxLayout()
        default_mon_iface = "wlan0mon"
        default_bssid = "AA:BB:CC:DD:EE:FF"
        default_channel = 6
        default_pmkid_prefix = "gui_pmkid"

        capture_pmkid_btn = QPushButton(f"Capture PMKID (Target: {default_bssid or 'All'})")
        capture_pmkid_btn.clicked.connect(
            lambda: self.run_task_in_thread(pmkid_module.capture_pmkid_hcxdumptool, default_mon_iface,
                                            default_pmkid_prefix, target_bssid=default_bssid, channel=default_channel,
                                            timeout=60)
        )
        layout.addWidget(capture_pmkid_btn)

        crack_pmkid_btn = QPushButton("Crack PMKID (Hashcat)")
        crack_pmkid_btn.clicked.connect(self._handle_pmkid_crack)
        layout.addWidget(crack_pmkid_btn)
        group.setLayout(layout)
        return group

    def _handle_pmkid_crack(self):
        placeholder_wordlist = "/usr/share/wordlists/rockyou.txt"

        def pmkid_crack_sequence():
            pcap_file, ok = QInputDialog.getText(self, "PMKID Crack - Step 1",
                                                 "Enter path to captured .pcapng file for PMKID (from hcxdumptool):")
            if not (ok and pcap_file and os.path.exists(pcap_file)):
                QMessageBox.warning(self, "PMKID Crack", "Valid .pcapng file path is required.")
                return "PMKID cracking cancelled: No valid pcapng file."

            wordlist_file, ok = QInputDialog.getText(self, "PMKID Crack - Step 2", "Enter path to wordlist file:",
                                                     text=placeholder_wordlist)
            if not (ok and wordlist_file and os.path.exists(wordlist_file)):
                QMessageBox.warning(self, "PMKID Crack", "Valid wordlist file path is required.")
                return "PMKID cracking cancelled: No valid wordlist file."

            print(f"[*] Converting PCAPNG: {pcap_file} for PMKID cracking.")
            hash_file = pmkid_module.convert_pcapng_to_hccapx(pcap_file)
            if hash_file and os.path.exists(hash_file):
                print(f"[*] Cracking Hash File: {hash_file} with Wordlist: {wordlist_file}")
                found_pass = pmkid_module.crack_pmkid_hashcat(hash_file, wordlist_file)
                return f"PMKID Crack Result: {found_pass}" if found_pass else "PMKID Crack: Password not found."
            else:
                return "PMKID cracking failed: Conversion step produced no valid hash file."

        self.run_task_in_thread(pmkid_crack_sequence)

    def create_deauth_section(self):
        group = QGroupBox("Deauthentication Attack (aireplay-ng)")
        layout = QVBoxLayout()
        default_mon_iface = "wlan0mon"
        default_target_mac = "FF:FF:FF:FF:FF:FF"
        default_ap_mac = "AA:BB:CC:DD:EE:FF"

        deauth_btn = QPushButton(f"Deauth Clients from AP {default_ap_mac}")
        deauth_btn.clicked.connect(
            lambda: self.run_task_in_thread(deauth_attack.deauth_attack, default_mon_iface, default_ap_mac,
                                            target_mac=default_target_mac, num_packets=20)
        )
        layout.addWidget(deauth_btn)
        group.setLayout(layout)
        return group

    def create_evil_twin_section(self):
        group = QGroupBox("Evil Twin / Rogue AP Attacks")
        layout = QVBoxLayout()
        default_ap_iface = "wlan0"
        default_internet_iface = "eth0"
        default_essid = "Free_WiFi_Evil"

        start_twin_btn = QPushButton(f"Start Evil Twin AP ({default_essid})")
        start_twin_btn.clicked.connect(
            lambda: self._start_evil_twin(default_ap_iface, default_internet_iface, default_essid))
        layout.addWidget(start_twin_btn)

        stop_twin_btn = QPushButton("Stop Evil Twin AP")
        stop_twin_btn.clicked.connect(self._stop_evil_twin)
        layout.addWidget(stop_twin_btn)

        wifiphisher_btn = QPushButton("Start Wifiphisher Attack")
        wifiphisher_btn.clicked.connect(
            lambda: self.run_task_in_thread(wifiphisher_attack.start_wifiphisher_attack, default_ap_iface,
                                            essid=default_essid, internet_interface=default_internet_iface)
        )
        layout.addWidget(wifiphisher_btn)

        stop_wifiphisher_btn = QPushButton("Stop Wifiphisher (if started by this app)")
        stop_wifiphisher_btn.clicked.connect(
            lambda: self.run_task_in_thread(wifiphisher_attack._stop_wifiphisher_process))
        layout.addWidget(stop_wifiphisher_btn)
        group.setLayout(layout)
        return group

    def _start_evil_twin(self, ap_iface, internet_iface, essid, passphrase=None):
        if self.evil_twin_instance:
            QMessageBox.warning(self, "Evil Twin", "Evil Twin already active or configured. Stop it first.")
            return
        print(f"[*] Initializing Evil Twin: AP={ap_iface}, Internet={internet_iface}, ESSID={essid}")
        self.evil_twin_instance = evil_twin.EvilTwinAttack(
            ap_interface=ap_iface, internet_interface=internet_iface, essid=essid, passphrase=passphrase
        )
        self.run_task_in_thread(self.evil_twin_instance.start)

    def _stop_evil_twin(self):
        if self.evil_twin_instance:
            print("[*] Stopping Evil Twin AP...")
            self.run_task_in_thread(self._perform_evil_twin_stop_and_clear)
        else:
            QMessageBox.information(self, "Evil Twin", "Evil Twin AP is not currently active.")

    def _perform_evil_twin_stop_and_clear(self):
        if self.evil_twin_instance:
            self.evil_twin_instance.stop()
            self.evil_twin_instance = None
            return "Evil Twin stopped."
        return "Evil Twin was not active."

    def create_wps_section(self):
        group = QGroupBox("WPS Attacks (Reaver, Bully, Wash)")
        layout = QVBoxLayout()
        default_mon_iface = "wlan0mon"
        default_bssid = "AA:BB:CC:DD:EE:FF"
        default_channel = 6
        default_essid = "TargetNetwork_WPS"

        scan_wps_btn = QPushButton(f"Scan WPS Networks (Wash on {default_mon_iface})")
        scan_wps_btn.clicked.connect(
            lambda: self.run_task_in_thread(wps_attack.scan_wps_networks_wash, default_mon_iface,
                                            channel=default_channel, timeout_seconds=30)
        )
        layout.addWidget(scan_wps_btn)

        reaver_btn = QPushButton(f"Start Reaver Attack (Target: {default_bssid})")
        reaver_btn.clicked.connect(
            lambda: self.run_task_in_thread(wps_attack.wps_attack_reaver, default_mon_iface, default_bssid,
                                            channel=default_channel, essid=default_essid)
        )
        layout.addWidget(reaver_btn)

        bully_btn = QPushButton(f"Start Bully Attack (Target: {default_bssid})")
        bully_btn.clicked.connect(
            lambda: self.run_task_in_thread(wps_attack.wps_attack_bully, default_mon_iface, default_bssid,
                                            channel=default_channel, essid=default_essid)
        )
        layout.addWidget(bully_btn)

        stop_reaver_btn = QPushButton(f"Stop Reaver for {default_bssid}")
        stop_reaver_btn.clicked.connect(lambda: self.run_task_in_thread(wps_attack._stop_attack_process,
                                                                        f"reaver_{default_bssid.replace(':', '')}"))
        layout.addWidget(stop_reaver_btn)

        stop_bully_btn = QPushButton(f"Stop Bully for {default_bssid}")
        stop_bully_btn.clicked.connect(
            lambda: self.run_task_in_thread(wps_attack._stop_attack_process, f"bully_{default_bssid.replace(':', '')}"))
        layout.addWidget(stop_bully_btn)
        group.setLayout(layout)
        return group

    def create_password_section(self):
        group = QGroupBox("Online Password Attacks (Crunch, Hydra)")
        layout = QVBoxLayout()
        default_crunch_output = "/tmp/gui_wordlist.txt"
        default_wordlist = "/usr/share/wordlists/rockyou.txt"
        default_target_ip = "192.168.1.100"
        default_username = "admin"
        default_userlist = "/tmp/common_users.txt"

        crunch_btn = QPushButton("Generate Wordlist (Crunch)")
        crunch_btn.clicked.connect(
            lambda: self.run_task_in_thread(password_attack.generate_wordlist_crunch, default_crunch_output, min_len=6,
                                            max_len=8, charset="abcdef123")
        )
        layout.addWidget(crunch_btn)

        brute_force_btn = QPushButton(f"Brute Force SSH Login ({default_target_ip})")
        brute_force_btn.clicked.connect(
            lambda: self.run_task_in_thread(password_attack.run_hydra_attack, default_target_ip, "ssh",
                                            username=default_username, password_list_file=default_wordlist)
        )
        layout.addWidget(brute_force_btn)

        pass_spray_btn = QPushButton(f"Password Spray HTTP-GET ({default_target_ip})")
        pass_spray_btn.clicked.connect(
            lambda: self.run_task_in_thread(password_attack.run_hydra_attack, default_target_ip, "http-get",
                                            user_list_file=default_userlist, password="Password123")
        )
        layout.addWidget(pass_spray_btn)
        group.setLayout(layout)
        return group

    def create_automated_attacks_section(self):
        group = QGroupBox("Automated Attack Suites (Wifite2, Fluxion)")
        layout = QVBoxLayout()
        default_iface = "wlan0"

        wifite_btn = QPushButton(f"Start Wifite2 ({default_iface})")
        wifite_btn.clicked.connect(
            lambda: self.run_task_in_thread(automated_attack.run_automated_attack, default_iface))
        layout.addWidget(wifite_btn)

        fluxion_btn = QPushButton(f"Start Fluxion ({default_iface})")
        fluxion_btn.clicked.connect(lambda: self.run_task_in_thread(automated_attack.run_fluxion_attack, default_iface))
        layout.addWidget(fluxion_btn)
        group.setLayout(layout)
        return group

    def pyrit_brute_force(self, handshake_file, wordlist):
        print(f"[+] Starting Pyrit brute-force on {handshake_file} using {wordlist}...")
        if not (os.path.exists(handshake_file) and os.path.exists(wordlist)):
            msg = f"Pyrit Error: Handshake file '{handshake_file}' or wordlist '{wordlist}' not found."
            print(f"[-] {msg}")
            return msg

        if not shutil.which("pyrit"):  # shutil was imported at the top
            msg = "Pyrit command not found. Please install Pyrit."
            print(f"[!] {msg}")
            return msg

        command = ["pyrit", "-r", handshake_file, "-i", wordlist, "attack_db"]
        try:
            result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=3600)
            output = f"Pyrit STDOUT:\n{result.stdout}\nPyrit STDERR:\n{result.stderr}"  # Ensure result is not None
            if result.returncode == 0:
                # Ensure result.stdout is not None before checking 'in'
                if result.stdout and ("The password is" in result.stdout or "AccessPoint found" in result.stdout):
                    match = re.search(r"The password is: '?(.+?)'?", result.stdout)  # re was imported at the top
                    if match:
                        return f"Pyrit SUCCESS: Password found: {match.group(1)}"
                    return f"Pyrit SUCCESS: Password potentially found. Check output:\n{output}"
                return f"Pyrit finished. No password explicitly found in output.\n{output}"
            else:
                return f"Pyrit failed (code {result.returncode}).\n{output}"
        except subprocess.TimeoutExpired:
            return "Pyrit command timed out."
        except Exception as e:
            return f"Error running Pyrit: {str(e)}"

    def emergency_stop_all_actions(self):
        print("[!!!] EMERGENCY STOP ACTIVATED [!!!]")
        print("[*] Stopping active QThreads...")
        for worker in list(self.active_workers):
            if worker.isRunning():
                print(f"    Terminating QThread for task: {worker.function.__name__}...")
                worker.quit()
                if not worker.wait(2000):
                    print(f"    QThread for {worker.function.__name__} did not quit, terminating forcefully.")
                    worker.terminate()
                    worker.wait()
        self.active_workers.clear()
        print("[+] QThreads processed.")

        if self.evil_twin_instance:
            print("[*] Attempting to stop Evil Twin instance...")
            try:
                self.evil_twin_instance.stop()
                self.evil_twin_instance = None
                print("[+] Evil Twin stop method called.")
            except Exception as e:
                print(f"[-] Error stopping Evil Twin: {e}")

        print("[*] Calling module-specific global stop functions (if they exist)...")

        # Modules with _stop_all_background_processes (list based)
        for mod_name_str in ['handshake', 'pmkid_module', 'password_attack']:
            mod = getattr(sys.modules.get(f"modules.{mod_name_str}"), None)
            if mod and hasattr(mod, '_stop_all_background_processes'):
                print(f"    Stopping processes for module: {mod.__name__}")
                mod._stop_all_background_processes()

        # Modules with specific stop functions and dict-based process tracking
        for mod_name_str, stop_func_name, proc_dict_name in [
            ('wps_attack', '_stop_attack_process', 'running_attack_processes'),
            ('scanning_recon', '_stop_interactive_tool', 'running_processes')
        ]:
            mod = getattr(sys.modules.get(f"modules.{mod_name_str}"), None)
            mod_stop_func = getattr(mod, stop_func_name, None)
            running_procs_dict = getattr(mod, proc_dict_name, None)

            if mod and mod_stop_func and isinstance(running_procs_dict, dict):  # Check if it's a dict
                print(f"    Stopping processes for module: {mod.__name__} via its dict '{proc_dict_name}'")
                for key in list(running_procs_dict.keys()):
                    mod_stop_func(key)  # Assumes key is the first arg to stop_func

        if hasattr(wifiphisher_attack, '_stop_wifiphisher_process'):
            print("    Stopping Wifiphisher...")
            wifiphisher_attack._stop_wifiphisher_process()

        print("[+] Emergency stop sequence completed. Please verify in your terminal if any processes remain.")
        QMessageBox.information(self, "Emergency Stop",
                                "Attempted to stop all tracked actions. Please verify in terminal.")

    def closeEvent(self, event):
        print("[*] Main window closing. Initiating emergency stop...")
        self.emergency_stop_all_actions()
        sys.stdout = sys.__stdout__
        sys.stderr = sys.__stderr__
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())