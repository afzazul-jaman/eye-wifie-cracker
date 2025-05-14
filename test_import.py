# C:/Users/ankon/PycharmProjects/eye-wife/test_import.py
import sys
print("Current sys.path in test_import.py:", sys.path)

try:
    import modules.interface_monitor
    print("SUCCESS: Imported modules.interface_monitor from project root.")
except ImportError as e:
    print(f"FAILURE from project root: Could not import modules.interface_monitor. Error: {e}")
    # Let's see what's in the modules directory from Python's perspective
    import os
    modules_path = os.path.join(os.path.dirname(__file__), "modules")
    if os.path.exists(modules_path):
        print(f"Contents of '{modules_path}': {os.listdir(modules_path)}")
    else:
        print(f"'{modules_path}' does NOT exist.")