"""
File Integrity Checker - Secure File Monitor Tool
Author: Dinesh
GitHub: https://github.com/Dinesh1925

Features:
---------
✔️ GUI built with `ttkbootstrap` for modern look  
✔️ SHA-256 hashing for security  
✔️ Save and load hash state  
✔️ Detect file modifications, deletions, or new files  
✔️ Scheduled background scans  
✔️ Logging for audit and debugging

"""
import os
import hashlib
import json
import logging
import tkinter as tk
from tkinter import filedialog, messagebox
from tkinter.scrolledtext import ScrolledText
import ttkbootstrap as ttk
from ttkbootstrap.constants import *

# Configure logging
logging.basicConfig(
    filename="file_integrity_checker.log",
    level=logging.DEBUG,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logger.info("File Integrity Checker started.")

EXCLUDE_DIRS = ["/proc", "/sys", "/dev"]
SCAN_INTERVAL_MS = 60000

def calculate_hash(file_path):
    try:
        sha256 = hashlib.sha256()
        with open(file_path, "rb") as fp:
            for block in iter(lambda: fp.read(4096), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating hash for {file_path}: {e}")
        return None

def scan_directory(directory):
    logger.info(f"Scanning directory: {directory}")
    state = {}
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if not any(excl in os.path.join(root, d) for excl in EXCLUDE_DIRS)]
        for file in files:
            path = os.path.join(root, file)
            hash_val = calculate_hash(path)
            if hash_val:
                state[path] = hash_val
    return state

class FileIntegrityCheckerGUI(ttk.Window):
    def __init__(self):
        super().__init__(title="File Integrity Checker - By Dinesh", themename="darkly", size=(900, 650))
        self.initial_state = {}
        self.monitored_directory = ""
        self.scheduled_scan_active = False
        self.after_id = None
        self.create_widgets()

    def create_widgets(self):
        # Directory selection frame
        frame_dir = ttk.Frame(self)
        frame_dir.pack(fill=X, padx=10, pady=10)
        ttk.Label(frame_dir, text="Directory to Monitor:").pack(side=LEFT, padx=5)
        self.entry_dir = ttk.Entry(frame_dir, width=60)
        self.entry_dir.pack(side=LEFT, padx=5)
        ttk.Button(frame_dir, text="Select", command=self.select_directory, bootstyle=INFO).pack(side=LEFT, padx=5)

        # Button frame
        frame_buttons = ttk.Frame(self)
        frame_buttons.pack(fill=X, padx=10, pady=5)
        ttk.Button(frame_buttons, text="Calculate Initial Hashes", command=self.calculate_initial_hashes, bootstyle=PRIMARY).pack(side=LEFT, padx=5)
        ttk.Button(frame_buttons, text="Save State", command=self.save_state, bootstyle=SECONDARY).pack(side=LEFT, padx=5)
        ttk.Button(frame_buttons, text="Verify Integrity", command=self.verify_integrity, bootstyle=SUCCESS).pack(side=LEFT, padx=5)
        ttk.Button(frame_buttons, text="Start Scheduled Scan", command=self.start_scheduled_scan, bootstyle=WARNING).pack(side=LEFT, padx=5)
        ttk.Button(frame_buttons, text="Stop Scheduled Scan", command=self.stop_scheduled_scan, bootstyle=DANGER).pack(side=LEFT, padx=5)

        # Output area
        self.text_output = ScrolledText(self, wrap=tk.WORD, height=25)
        self.text_output.pack(fill=BOTH, padx=10, pady=10, expand=True)

        # Status label
        self.lbl_status = ttk.Label(self, text="Ready", font=("Segoe UI", 10, "bold"))
        self.lbl_status.pack(padx=10, pady=5)

    def select_directory(self):
        directory = filedialog.askdirectory(title="Select Directory to Monitor")
        if directory:
            self.monitored_directory = directory
            self.entry_dir.delete(0, tk.END)
            self.entry_dir.insert(0, directory)
            self.text_output.insert(tk.END, f"Selected directory: {directory}\n")
            self.lbl_status.config(text="Directory selected.")

    def calculate_initial_hashes(self):
        if not self.monitored_directory:
            messagebox.showerror("Error", "Please select a directory to monitor first.")
            return
        self.lbl_status.config(text="Calculating initial hashes...")
        self.update_idletasks()
        state = scan_directory(self.monitored_directory)
        self.initial_state = state.copy()
        self.text_output.insert(tk.END, "Initial hashes calculated:\n")
        for path, hash_val in state.items():
            self.text_output.insert(tk.END, f"{path}: {hash_val}\n")
        self.lbl_status.config(text="Initial hashes calculated.")

    def save_state(self):
        if not self.initial_state:
            messagebox.showerror("Error", "No state to save. Please calculate the hashes first.")
            return
        try:
            filename = os.path.join(self.monitored_directory, "integrity_state.json")
            with open(filename, "w") as f:
                json.dump(self.initial_state, f, indent=4)
            self.text_output.insert(tk.END, f"State saved in: {filename}\n")
            self.lbl_status.config(text="State saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving file: {e}")
            self.lbl_status.config(text="Error saving state.")

    def verify_integrity(self):
        if not self.initial_state:
            messagebox.showerror("Error", "Please calculate the initial hashes first.")
            return
        self.lbl_status.config(text="Verifying integrity...")
        self.update_idletasks()
        new_state = scan_directory(self.monitored_directory)
        modifications = []
        for path, initial_hash in self.initial_state.items():
            new_hash = new_state.get(path)
            if new_hash is None:
                modifications.append(f"File removed: {path}")
            elif new_hash != initial_hash:
                modifications.append(f"Modification detected in: {path}")
        for path in new_state:
            if path not in self.initial_state:
                modifications.append(f"New file detected: {path}")
        if modifications:
            msg = "\n".join(modifications)
            self.text_output.insert(tk.END, "Modifications detected:\n" + msg + "\n")
            messagebox.showwarning("Modifications Detected", msg)
        else:
            self.text_output.insert(tk.END, "No modifications detected.\n")
            messagebox.showinfo("Integrity Verification", "No modifications detected.")
        self.lbl_status.config(text="Integrity verification completed.")

    def start_scheduled_scan(self):
        if not self.monitored_directory:
            messagebox.showerror("Error", "Please select a directory to monitor first.")
            return
        self.lbl_status.config(text="Scheduled scan started.")
        self.scheduled_scan_active = True
        self.scheduled_scan()

    def scheduled_scan(self):
        if self.scheduled_scan_active:
            self.verify_integrity()
            self.after_id = self.after(SCAN_INTERVAL_MS, self.scheduled_scan)

    def stop_scheduled_scan(self):
        self.scheduled_scan_active = False
        if self.after_id:
            self.after_cancel(self.after_id)
        self.lbl_status.config(text="Scheduled scan stopped.")

if __name__ == "__main__":
    app = FileIntegrityCheckerGUI()
    app.mainloop()
