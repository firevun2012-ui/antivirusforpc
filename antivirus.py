import os
import time
import shutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox
import datetime
import hashlib
import gc

# Third-party libraries
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# -------------------------
# MOCK/CUSTOM MODULES
# -------------------------
try:
    import custom_defender
    import clam_scanner
except ImportError:
    class MockScanner:
        def scan_file(self, path):
            if "eicar" in path.lower(): return True, "EICAR-Test"
            return False, "Clean"


    custom_defender = MockScanner()
    clam_scanner = MockScanner()

# -------------------------
# CONFIGURATION & GLOBAL SETTINGS
# -------------------------
USER_HOME = os.path.expanduser("~")
WATCH_TARGETS = [os.path.join(USER_HOME, "Downloads"), os.path.join(USER_HOME, "Desktop")]
EXCLUDED_DIRS = ["C:\\Windows", "C:\\Program Files"]
QUARANTINE = "C:\\_quarantine"
os.makedirs(QUARANTINE, exist_ok=True)

already_scanned_hashes = set()
detected_threats = []
engine_logs = []
is_gui_open = False
protection_active = True


# -------------------------
# CORE UTILITIES
# -------------------------
def calculate_sha256(path):
    sha256_hash = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""): sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except:
        return None


def log_event(message):
    ts = datetime.datetime.now().strftime("%H:%M:%S")
    full_msg = f"[{ts}] {message}"
    engine_logs.append(full_msg)
    if len(engine_logs) > 500: engine_logs.pop(0)
    print(full_msg)


def should_scan(path):
    exts = [".exe", ".dll", ".bat", ".cmd", ".scr", ".ps1", ".vbs", ".js", ".msi"]
    is_valid = os.path.splitext(path)[1].lower() in exts
    return is_valid and not any(path.startswith(d) for d in EXCLUDED_DIRS)


def wait_for_file_stability(path):
    try:
        l_size = -1
        for _ in range(5):
            c_size = os.path.getsize(path)
            if c_size == l_size and c_size > 0: return True
            l_size = c_size;
            time.sleep(0.4)
        return False
    except:
        return False


def permanent_delete(path):
    try:
        if not os.path.exists(path): return True
        gc.collect();
        time.sleep(0.1)
        os.chmod(path, 0o777)
        os.remove(path)
        log_event(f"SUCCESS: {os.path.basename(path)} has been purged.")
        return True
    except:
        try:
            with open(path, 'wb') as f:
                f.write(b'\x00')
            os.remove(path)
            return True
        except Exception as e:
            log_event(f"FORCE ERROR: {os.path.basename(path)} is locked -> {e}")
            return False


def show_windows_alert():
    if not is_gui_open:
        def alert_t():
            root = tk.Tk();
            root.withdraw()
            if messagebox.askyesno("AegisCore ALERT", "Threat detected! Open console?"): launch_gui()
            root.destroy()

        threading.Thread(target=alert_t, daemon=True).start()


# -------------------------
# SCAN ENGINE
# -------------------------
def scan_engine(path):
    if not os.path.isfile(path) or not should_scan(path): return
    f_hash = calculate_sha256(path)
    if not f_hash or f_hash in already_scanned_hashes: return
    if not wait_for_file_stability(path): return
    log_event(f"ANALYZING: {os.path.basename(path)}")
    r1, res1 = custom_defender.scan_file(path)
    r2, res2 = clam_scanner.scan_file(path)
    if r1 or r2:
        reason = res1 if r1 else res2
        log_event(f"THREAT: {reason} in {os.path.basename(path)}")
        if path not in detected_threats:
            detected_threats.append(path);
            show_windows_alert()
    else:
        already_scanned_hashes.add(f_hash)
        log_event(f"CLEAN: {os.path.basename(path)}")


# -------------------------
# WATCHDOG SERVICE
# -------------------------
class RealTimeHandler(FileSystemEventHandler):
    def on_created(self, e):
        if not e.is_directory: scan_engine(e.src_path)

    def on_modified(self, e):
        if not e.is_directory: scan_engine(e.src_path)


def start_service():
    global protection_active
    obs = Observer()
    for f in WATCH_TARGETS:
        if os.path.exists(f): obs.schedule(RealTimeHandler(), f, recursive=False)
    obs.start()
    try:
        while protection_active: time.sleep(1)
    except:
        obs.stop()
    obs.join()


# -------------------------
# PRO GUI INTERFACE
# -------------------------
class AegisGUI:
    def __init__(self):
        global is_gui_open
        is_gui_open = True;
        self.root = tk.Tk()
        self.root.title("AegisCore Advanced Suite v2.5");
        self.root.geometry("1100x650")
        self.root.configure(bg="#0a0a0a");
        self.setup_ui();
        self.refresh_ui()

    def setup_ui(self):
        t_bar = tk.Frame(self.root, bg="#1a1a1a", height=50);
        t_bar.pack(side=tk.TOP, fill=tk.X)
        tk.Label(t_bar, text="🛡 AEGISCORE", bg="#1a1a1a", fg="#00ff41", font=("Arial", 12, "bold")).pack(side=tk.LEFT,
                                                                                                         padx=20)
        main_c = tk.Frame(self.root, bg="#0a0a0a");
        main_c.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        lt = tk.LabelFrame(main_c, text=" THREATS ", bg="#0a0a0a", fg="red", font=("Consolas", 10))
        lt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5)
        self.t_box = tk.Listbox(lt, bg="#050505", fg="#ff4d4d", font=("Consolas", 9), borderwidth=0)
        self.t_box.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        tk.Button(lt, text="TERMINATE", bg="#330000", fg="white", command=self.action_del).pack(fill=tk.X, pady=5)

        rt = tk.LabelFrame(main_c, text=" LOGS ", bg="#0a0a0a", fg="#00ff41", font=("Consolas", 10))
        rt.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=5)
        self.c_out = tk.Text(rt, bg="#050505", fg="#00ff41", font=("Consolas", 8), state=tk.DISABLED)
        self.c_out.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def action_del(self):
        sel = self.t_box.curselection()
        if not sel: return
        t = self.t_box.get(sel[0])
        if permanent_delete(t):
            if t in detected_threats: detected_threats.remove(t)
            self.t_box.delete(sel[0]);
            messagebox.showinfo("OK", "Threat Purged!")

    def refresh_ui(self):
        curr = self.t_box.get(0, tk.END)
        for t in detected_threats:
            if t not in curr: self.t_box.insert(tk.END, t)
        self.c_out.config(state=tk.NORMAL);
        self.c_out.delete('1.0', tk.END)
        for l in engine_logs[-20:]: self.c_out.insert(tk.END, l + "\n")
        self.c_out.see(tk.END);
        self.c_out.config(state=tk.DISABLED)
        self.root.after(800, self.refresh_ui)

    def on_exit(self):
        global is_gui_open;
        is_gui_open = False;
        self.root.destroy()


def launch_gui():
    if not is_gui_open: AegisGUI().root.mainloop()


if __name__ == "__main__":
    log_event("--- AEGIS INITIALIZED ---")
    threading.Thread(target=start_service, daemon=True).start()
    launch_gui()
    try:
        while True: time.sleep(5)
    except:
        protection_active = False

# LINE 330
# LINE 331
# LINE 332
# LINE 333