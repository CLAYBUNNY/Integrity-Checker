# 🔐 File Integrity Checker

A modern Python-based GUI tool for verifying file integrity and detecting unauthorized modifications using SHA-256 hashes.

![Python](https://img.shields.io/badge/Python-3.10+-blue?logo=python)
![Tkinter](https://img.shields.io/badge/GUI-Tkinter%2Bttkbootstrap-purple?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Author](https://img.shields.io/badge/Author-Bunny%20Bunny%20(Dinesh)-orange)

---

## 📌 About the Project

**File Integrity Checker** is a tool designed to monitor a selected directory for any changes in files. It calculates secure SHA-256 hashes for all files and checks periodically for modifications, additions, or deletions — ensuring that your data hasn’t been tampered with.

This is especially useful for:
- Cybersecurity students and professionals
- System admins who want file monitoring
- Use in digital forensics labs
- File change detection and compliance auditing

---

## 🎯 Key Features

✅ GUI built with [`ttkbootstrap`](https://ttkbootstrap.readthedocs.io/) (modern look)  
✅ SHA-256 hashing for strong security  
✅ Detect file modifications, new files, and deletions  
✅ Save and load file state (JSON format)  
✅ Scheduled automatic scanning  
✅ Logging system (`file_integrity_checker.log`)

---

## 🧠 How It Works

1. Select a directory to monitor
2. Calculate and save initial hashes
3. Verify integrity on demand or enable scheduled scans
4. Get notified of any changes via GUI and logs

---

## 🚀 Getting Started

### 🔧 Prerequisites

- Python 3.10 or above  
- `ttkbootstrap` (install via pip)

### 📦 Installation

```bash
git clone https://github.com/your-username/FileIntegrityChecker.git
cd FileIntegrityChecker
pip install ttkbootstrap

