import tkinter as tk
from tkinter import messagebox, filedialog, ttk, simpledialog, scrolledtext
import threading
import time
import hashlib
import os
import glob
import re
import json
import collections
import psutil
import requests
import datetime
import subprocess
import sys
import queue # Added for thread-safe logging and alerts
import csv # Import the csv module
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import winsound  # Windows-specific
import smtplib
import asyncio

def start_async_tasks(self):
    asyncio.run(self.async_periodic_tasks())

async def async_periodic_tasks(self):
    while self.monitoring_active:
        await asyncio.sleep(self.config.get('monitoring_interval_sec', 10))
        # Run non-UI tasks asynchronously
        await asyncio.gather(
            self.fetch_threat_feed_async(),
            self.analyze_logs_async(),
            # Add other async tasks
        )

# Ensure scapy is available
try:
    from scapy.all import sniff, TCP, IP, UDP, DNS # Added UDP, DNS
    from scapy.layers.dns import DNSQR # Added DNSQR
    from scapy.error import Scapy_Exception # Import Scapy_Exception for specific errors
except ImportError:
    messagebox.showerror("Dependency Error", "Scapy not found. Please install it:\n'pip install scapy'")
    sys.exit(1)
except Scapy_Exception as e:
     # Catch other potential Scapy init errors
     messagebox.showerror("Scapy Error", f"Error initializing Scapy: {e}\nEnsure Npcap/WinPcap (Windows) or libpcap (Linux/macOS) is installed.")
     sys.exit(1)


# Constants and defaults
CONFIG_FILE = "config.json"
STATE_FILE = "state.json"
DEFAULT_CONFIG = {
    "monitored_files": [os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32\\drivers\\etc\\hosts')],
    "log_paths": [],
    "trusted_process_dirs": [
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32'),
        os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System'),
        os.path.join(os.environ.get('ProgramFiles', 'C:\\Program Files')),
        os.path.join(os.environ.get('ProgramFiles(x86)', 'C:\\Program Files (x86)')),
        "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin"], # Common Linux/macOS paths
    "log_keywords": ["failed login", "error", "denied", "malicious"],
    "signatures_file": "signatures.txt",
    "signature_regex": False,
    "connection_anomaly_threshold": 200,
    "network_interface": None,
    "monitoring_interval_sec": 10,
    "threat_feed_url": "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
    "threat_feed_update_hours": 1,
    "bpf_filter": "tcp or udp", # Default filter
    "domain_threat_feed_url": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts", # Added domain threat feed
    "domain_threat_feed_update_hours": 6 # Added domain threat feed update interval
}

# --- Severity Levels (for alerts) ---
SEVERITY_LEVELS = ["Info", "Low", "Medium", "High", "Critical"]

# Define CREATE_NO_WINDOW for Windows subprocess calls
CREATE_NO_WINDOW = 0x08000000 if sys.platform.startswith('win') else 0


def calculate_file_hash(filepath):
    if not os.path.exists(filepath):
        return None
    hasher = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        # Log the error but don't raise
        print(f"Error hashing file {filepath}: {e}")
        return None


class SecurityMonitorApp:
    def __init__(self, master):
        self.master = master
        master.title("Enhanced Security Monitor")

        self.full_log_history = []

        # Initialize callback IDs to None
        self.periodic_task_id = None
        self._process_queues_id = None
        self._plot_update_id = None

        # Data structures
        self.alerts = []
        # Modified signatures structure to include category and severity
        self.signatures = [] # Will store dicts: {"pattern": "...", "category": "...", "severity": "..."}
        self.tcp_sessions = {}
        self.connection_counts = collections.defaultdict(int)
        self.threat_ips = set()
        self.threat_domains = set() # Added for domain blacklisting
        self.listening_ports = {} # Added for listening port monitoring { (ip, port, proto): process_info }

        self.monitoring_active = False
        self.monitoring_threads = []
        self.stop_event = threading.Event()

        # Thread-safe communication queues
        self.log_queue = queue.Queue() # Queue for log messages
        self.alert_queue = queue.Queue() # Queue for alert messages

        # Persistent state
        self.previous_file_hashes = {}
        self.log_read_positions = {}
        self.previous_listening_ports = {} # Added for listening port monitoring state

        # Load config & state
        self.config = self.load_config()
        self.load_state()

        # Setup UI FIRST, so UI elements exist when needed
        self.setup_ui()

        # Load signatures AFTER UI is set up
        self.load_signatures()

        # Start queue processing (runs in main thread)
        # Store the ID returned by master.after
        self._process_queues_id = self.master.after(100, self.process_queues)

        # Schedule initial threat feed updates
        self.schedule_threat_feed_update() # For IPs
        self.schedule_domain_threat_feed_update() # For Domains

        # Now, self.log is available for use - but use the queue!
        self.log("Application started.")

    def process_queues(self):
        try:
            # Process log messages
            while not self.log_queue.empty():
                msg = self.log_queue.get()
                # Store full logs for filtering
                self.full_log_history.append(msg)
                # Only display if no filter or message matches filter
                if not getattr(self, 'log_filtered', False) or (self.log_filter_var.get().lower() in msg.lower()):
                    self._update_log_text_ui(msg)
                self.log_queue.task_done()
            # Process alerts
            while not self.alert_queue.empty():
                alert = self.alert_queue.get()
                self.alerts.append(alert)
                # Only display if no filter or alert source matches
                if not getattr(self, 'alerts_filtered', False) or (self.alert_source_filter_var.get().lower() in alert.get('source','').lower()):
                    self._add_alert_to_ui(alert)
                self.alert_queue.task_done()
        except Exception as e:
            print(f"Error processing queues: {e}")

        # Reschedule
        if self.master and not self.stop_event.is_set():
            self._process_queues_id = self.master.after(100, self.process_queues)

    # --- Thread-safe Logging and Alerting ---
    def _update_log_text_ui(self, message):
        """Updates the log text widget (called in the main thread)."""
        try:
            self.log_text.config(state=tk.NORMAL)
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            self.log_text.insert(tk.END, f"[{timestamp}] {message}\n")
            self.log_text.see(tk.END)
            self.log_text.config(state=tk.DISABLED)
        except tk.TclError:
            pass # Avoid errors if the widget is destroyed

    def log(self, message):
        """Adds a message to the log queue from any thread."""
        # Ensure the message is a string
        self.log_queue.put(str(message))

    def apply_log_filter(self):
        filter_text = self.log_filter_var.get().lower()
        self.log_filtered = True
        # Rebuild log with filter: for simplicity, just re-insert logs matching filter
        self._update_log_text_ui('')  # Clear
        for msg in self.full_log_history:
            if filter_text in msg.lower():
                self._update_log_text_ui(msg)

    def clear_log_filter(self):
        self.log_filtered = False
        self._update_log_text_ui('')  # Clear
        for msg in self.full_log_history:
            self._update_log_text_ui(msg)
            self.full_log_history.append(msg)

    def apply_alert_filter(self):
        source_filter = self.alert_source_filter_var.get().lower()
        self.alerts_filtered = True
        # Rebuild alert list
        self.alerts_treeview.delete(*self.alerts_treeview.get_children())
        for alert in self.alerts:
            if source_filter in alert.get('source', '').lower():
                self._add_alert_to_ui(alert)

    def clear_alert_filter(self):
        self.alerts_filtered = False
        self.refresh_alerts_ui()

    def refresh_alerts_ui(self):
        self.alerts_treeview.delete(*self.alerts_treeview.get_children())
        for alert in self.alerts:
            self._add_alert_to_ui(alert)

    def show_alert(self, alert_type, description, severity="Info", source="N/A", category="N/A"):
        """Adds an alert to the alert queue from any thread."""
        alert = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": alert_type,
            "description": description,
            "severity": severity,
            "source": source,
            "category": category
        }
        self.alert_queue.put(alert)
        # Also log the alert for immediate visibility in the main log
        # Use self.log which is thread-safe
        self.log(f"ALERT [{severity}] ({alert_type}): {description} [Source: {source}, Category: {category}]")


    def _add_alert_to_ui(self, alert):
        """Adds an alert to the alerts Treeview (called in the main thread)."""
        self.alerts.append(alert) # Store alerts in a list (optional, for later export)
        # Ensure severity is a string for the Treeview
        display_severity = str(alert.get("severity", "Unknown"))
        self.alerts_treeview.insert(
            "", tk.END,
            values=(alert.get("timestamp", "N/A"), alert.get("type", "Unknown"), display_severity, alert.get("source", "N/A"), alert.get("category", "N/A"), alert.get("description", "N/A"))
        )
        # Scroll to the bottom of the alerts list
        self.alerts_treeview.yview_moveto(1)


    def process_queues(self):
        """Processes messages from the log and alert queues (runs in main thread)."""
        # Add a print here to confirm this function is being called at all
        # print("Processing queues...") # Temporary debug print - remove later

        try:
            # Check if monitoring is still active (important for when stopping)
            if not self.monitoring_active and self.log_queue.empty() and self.alert_queue.empty():
                 self.log("Queue processing loop stopping as monitoring is inactive and queues are empty.")
                 return # Stop rescheduling if monitoring is off and queues are clear

            while not self.log_queue.empty():
                message = self.log_queue.get()
                self._update_log_text_ui(message)
                self.log_queue.task_done()

            while not self.alert_queue.empty():
                alert = self.alert_queue.get()
                self._add_alert_to_ui(alert)
                self.alert_queue.task_done()

        except Exception as e:
            # Log any unexpected errors during queue processing
            # This might not appear in the log if the UI update fails, but it's worth trying
            print(f"Error during queue processing: {e}")
            # Attempt to show an alert for critical issues, though UI might be unresponsive
            try:
                 self.show_alert("Internal Error", f"Error processing queues: {e}", severity="Critical", category="System Issue")
            except:
                 pass # Avoid crashing if show_alert fails

        finally:
             # Always reschedule itself, even if an error occurred, to attempt recovery
             # Only reschedule if the master window hasn't been destroyed
             if self.master and not self.stop_event.is_set(): # Check stop_event as well
                 self._process_queues_id = self.master.after(100, self.process_queues)

    # --- UI Setup ---
    def setup_ui(self):
        # Create the main notebook
        self.notebook = ttk.Notebook(self.master)
        self.notebook.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

        filter_frame = ttk.Frame(self.master)
        filter_frame.pack(fill='x', padx=10, pady=2)
    
        ttk.Label(filter_frame, text="Log Filter:").pack(side='left')
        self.log_filter_var = tk.StringVar()
        ttk.Entry(filter_frame, textvariable=self.log_filter_var, width=20).pack(side='left', padx=5)
        ttk.Button(filter_frame, text="Apply Log Filter", command=self.apply_log_filter).pack(side='left', padx=5)
        ttk.Button(filter_frame, text="Clear Log Filter", command=self.clear_log_filter).pack(side='left', padx=5)
    
        # Similarly for alerts
        alert_filter_frame = ttk.Frame(self.master)
        alert_filter_frame.pack(fill='x', padx=10, pady=2)
    
        ttk.Label(alert_filter_frame, text="Alert Filter:").pack(side='left')
        self.alert_source_filter_var = tk.StringVar()
        ttk.Entry(alert_filter_frame, textvariable=self.alert_source_filter_var, width=20).pack(side='left', padx=5)
        ttk.Button(alert_filter_frame, text="Apply Alert Filter", command=self.apply_alert_filter).pack(side='left', padx=5)
        ttk.Button(alert_filter_frame, text="Clear Alert Filter", command=self.clear_alert_filter).pack(side='left', padx=5)

        # Tab 1: Monitoring Log
        log_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(log_frame, text='Monitoring Log')

        self.log_text = scrolledtext.ScrolledText(log_frame, height=15, width=80)
        self.log_text.pack(padx=0, pady=0, fill=tk.BOTH, expand=True)
        self.log_text.config(state=tk.DISABLED, bg="black", fg="lime green")

        # Tab 2: Configuration (Add your config UI elements here)
        config_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(config_frame, text='Configuration')
        self.setup_config_tab(config_frame) # Call a method to set up config tab

        # Tab 3: Signatures (Add your signature UI elements here)
        signatures_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(signatures_frame, text='Signatures')
        self.setup_signatures_tab(signatures_frame) # Call a method to set up signatures tab

        # Tab 4: Alerts Dashboard (New Tab)
        alerts_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(alerts_frame, text='Alerts Dashboard')
        self.setup_alerts_tab(alerts_frame) # Call a method to set up alerts tab

        # Tab 5: Dashboard/Visualization (New Tab)
        dashboard_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(dashboard_frame, text='Dashboard')
        self.setup_dashboard_tab(dashboard_frame)

        # --- Control Buttons (remain outside the notebook, typically at the bottom) ---
        button_frame = ttk.Frame(self.master)
        button_frame.pack(pady=5)

        self.btn_start = ttk.Button(button_frame, text="Start Monitoring", command=self.start_monitoring)
        self.btn_start.pack(side=tk.LEFT, padx=5)
        self.btn_stop = ttk.Button(button_frame, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED)
        self.btn_stop.pack(side=tk.LEFT, padx=5)

        # Window close protocol
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)



    def setup_config_tab(self, parent_frame):
        # Placeholder for config UI elements - you will need to add them here
        # based on your existing code and new config options.
        # Examples: monitored files listbox, log paths entry, interval entry, etc.

        # Use a Canvas and Scrollbar for potentially long configuration lists
        canvas = tk.Canvas(parent_frame)
        scrollbar = ttk.Scrollbar(parent_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        bpf_frame = ttk.Frame(scrollable_frame) # Use scrollable_frame if using the canvas/scrollbar pattern
        bpf_frame.pack(anchor=tk.W, pady=(10, 0))
        ttk.Label(bpf_frame, text="BPF Filter (e.g., 'tcp port 80 or 443', 'udp port 53', 'ip'):").pack(anchor=tk.W)
        self.bpf_filter_var = tk.StringVar(value=self.config.get("bpf_filter", DEFAULT_CONFIG["bpf_filter"]))
        ttk.Entry(bpf_frame, textvariable=self.bpf_filter_var, width=60).pack(fill=tk.X, expand=False) # Adjust width as needed


        # Add config sections to scrollable_frame
        # Example: Monitored Files section (basic)
        files_label = ttk.Label(scrollable_frame, text="Monitored Files:")
        files_label.pack(anchor=tk.W, pady=(10, 0))

        self.files_listbox = tk.Listbox(scrollable_frame, height=5, width=50)
        self.files_listbox.pack(fill=tk.X, expand=False)
        self.update_files_listbox() # Populate listbox on load

        file_entry_frame = ttk.Frame(scrollable_frame)
        file_entry_frame.pack(fill=tk.X, pady=2)

        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_entry_frame, textvariable=self.file_path_var)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        browse_button = ttk.Button(file_entry_frame, text="Browse", command=self.browse_file)
        browse_button.pack(side=tk.LEFT)

        file_buttons_frame = ttk.Frame(scrollable_frame)
        file_buttons_frame.pack(fill=tk.X, pady=2)

        add_file_button = ttk.Button(file_buttons_frame, text="Add File", command=self.add_monitored_file)
        add_file_button.pack(side=tk.LEFT, padx=5)

        remove_file_button = ttk.Button(file_buttons_frame, text="Remove Selected", command=self.remove_selected_file)
        remove_file_button.pack(side=tk.LEFT, padx=5)

        clear_files_button = ttk.Button(file_buttons_frame, text="Clear All Files", command=self.clear_monitored_files)
        clear_files_button.pack(side=tk.LEFT, padx=5)

        # Add other config options here (log paths, keywords, intervals, thresholds, threat feed URLs, etc.)
        # Add them to scrollable_frame
        # Example: Monitoring Interval
        interval_frame = ttk.Frame(scrollable_frame)
        interval_frame.pack(anchor=tk.W, pady=(10, 0))
        ttk.Label(interval_frame, text="Monitoring Interval (sec):").pack(side=tk.LEFT)
        self.monitoring_interval_var = tk.IntVar(value=self.config.get("monitoring_interval_sec", 10))
        ttk.Spinbox(interval_frame, from_=1, to=300, textvariable=self.monitoring_interval_var, width=5).pack(side=tk.LEFT, padx=5)

        # Example: Connection Threshold
        conn_thresh_frame = ttk.Frame(scrollable_frame)
        conn_thresh_frame.pack(anchor=tk.W, pady=(5, 0))
        ttk.Label(conn_thresh_frame, text="Connection Anomaly Threshold:").pack(side=tk.LEFT)
        self.conn_threshold_var = tk.IntVar(value=self.config.get("connection_anomaly_threshold", 200))
        ttk.Spinbox(conn_thresh_frame, from_=10, to=10000, textvariable=self.conn_threshold_var, width=7).pack(side=tk.LEFT, padx=5)

        # Example: Network Interface
        interface_frame = ttk.Frame(scrollable_frame)
        interface_frame.pack(anchor=tk.W, pady=(5, 0))
        ttk.Label(interface_frame, text="Network Interface (leave blank for default):").pack(side=tk.LEFT)
        self.interface_var = tk.StringVar(value=self.config.get("network_interface", ""))
        ttk.Entry(interface_frame, textvariable=self.interface_var, width=30).pack(side=tk.LEFT, padx=5)

        # Example: Threat Feed URLs
        threat_feed_frame = ttk.Frame(scrollable_frame)
        threat_feed_frame.pack(anchor=tk.W, pady=(10, 0), fill=tk.X, expand=False) # Allow horizontal fill

        ttk.Label(threat_feed_frame, text="IP Threat Feed URL:").pack(anchor=tk.W)
        self.ip_threat_feed_var = tk.StringVar(value=self.config.get("threat_feed_url", DEFAULT_CONFIG["threat_feed_url"]))
        ttk.Entry(threat_feed_frame, textvariable=self.ip_threat_feed_var, width=60).pack(fill=tk.X, expand=True) # Allow horizontal fill

        ttk.Label(threat_feed_frame, text="Domain Threat Feed URL:").pack(anchor=tk.W, pady=(5, 0))
        self.domain_threat_feed_var = tk.StringVar(value=self.config.get("domain_threat_feed_url", DEFAULT_CONFIG["domain_threat_feed_url"]))
        ttk.Entry(threat_feed_frame, textvariable=self.domain_threat_feed_var, width=60).pack(fill=tk.X, expand=True) # Allow horizontal fill

        # Save Config Button
        ttk.Button(scrollable_frame, text="Save Configuration", command=self.save_config_from_ui).pack(pady=20)


    def save_config_from_ui(self):
        # Method to collect values from UI elements and save config
        try:
            self.config["monitoring_interval_sec"] = self.monitoring_interval_var.get()
            self.config["connection_anomaly_threshold"] = self.conn_threshold_var.get()
            self.config["network_interface"] = self.interface_var.get().strip()
            self.config["threat_feed_url"] = self.ip_threat_feed_var.get().strip()
            self.config["bpf_filter"] = self.bpf_filter_var.get().strip()
            self.config["domain_threat_feed_url"] = self.domain_threat_feed_var.get().strip()
            # Add other config variables from UI here
            self.save_config()
        except Exception as e:
            self.log(f"Error saving config from UI: {e}")
            messagebox.showerror("Save Error", f"Could not save configuration:\n{e}")

    def setup_signatures_tab(self, parent_frame):
        # --- Signature Management UI ---
        sig_label = ttk.Label(parent_frame, text="Signatures:")
        sig_label.pack(anchor=tk.W)

        # Frame for listbox and scrollbar
        sig_list_frame = ttk.Frame(parent_frame)
        sig_list_frame.pack(fill=tk.BOTH, expand=True)

        sig_scrollbar = ttk.Scrollbar(sig_list_frame)
        sig_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.sig_listbox = tk.Listbox(sig_list_frame, height=10, width=60, yscrollcommand=sig_scrollbar.set)
        self.sig_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sig_scrollbar.config(command=self.sig_listbox.yview)

        # No longer call refresh_signatures_listbox here, it's called after load_signatures in __init__


        # Signature entry fields
        entry_frame = ttk.Frame(parent_frame)
        entry_frame.pack(fill=tk.X, pady=5)

        ttk.Label(entry_frame, text="Pattern:").pack(side=tk.LEFT, padx=(0, 5))
        self.sig_pattern_var = tk.StringVar()
        sig_entry = ttk.Entry(entry_frame, textvariable=self.sig_pattern_var)
        sig_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        ttk.Label(entry_frame, text="Category:").pack(side=tk.LEFT, padx=(10, 5))
        self.sig_category_var = tk.StringVar(value="Network") # Default category
        self.sig_category_entry = ttk.Entry(entry_frame, textvariable=self.sig_category_var, width=15)
        self.sig_category_entry.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(entry_frame, text="Severity:").pack(side=tk.LEFT, padx=(10, 5))
        self.sig_severity_var = tk.StringVar(value="Medium") # Default severity
        self.sig_severity_dropdown = ttk.Combobox(entry_frame, textvariable=self.sig_severity_var, values=SEVERITY_LEVELS, state="readonly", width=10)
        self.sig_severity_dropdown.pack(side=tk.LEFT)


        # Regex checkbox
        regex_frame = ttk.Frame(parent_frame)
        regex_frame.pack(anchor=tk.W)
        self.signature_regex_var = tk.BooleanVar(value=self.config.get("signature_regex", False))
        ttk.Checkbutton(regex_frame, text="Use Regex for Signatures", variable=self.signature_regex_var).pack(side=tk.LEFT)


        # Buttons
        sig_button_frame = ttk.Frame(parent_frame)
        sig_button_frame.pack(pady=5)

        ttk.Button(sig_button_frame, text="Add Signature", command=self.add_signature_from_ui).pack(side=tk.LEFT, padx=5)
        ttk.Button(sig_button_frame, text="Edit Selected", command=self.edit_signature_from_ui).pack(side=tk.LEFT, padx=5)
        ttk.Button(sig_button_frame, text="Delete Selected", command=self.delete_signature_from_ui).pack(side=tk.LEFT, padx=5)

        # Bind listbox select to populate entry fields for editing
        self.sig_listbox.bind('<<ListboxSelect>>', self.load_selected_signature)

    def show_alert_details(self, event):
        selected = self.alerts_treeview.selection()
        if not selected:
            return
        item_id = selected[0]
        # Find the alert data corresponding to this item
        index = self.alerts_treeview.index(item_id)
        if index >= len(self.alerts):
            return
        alert = self.alerts[index]
        # Create popup window
        detail_win = tk.Toplevel(self.master)
        detail_win.title("Alert Details")
        # Display all alert info
        for key, val in alert.items():
            ttk.Label(detail_win, text=f"{key.capitalize()}: {val}").pack(anchor='w', padx=10, pady=2)
        # Optionally, add a ScrolledText for longer descriptions
        import tkinter.scrolledtext as st
        desc = alert.get('description', '')
        ttk.Label(detail_win, text="Full Description:").pack(anchor='w', padx=10, pady=(10,2))
        txt = st.ScrolledText(detail_win, height=10, width=80)
        txt.insert(tk.END, desc)
        txt.config(state=tk.DISABLED)
        txt.pack(padx=10, pady=2)

    def _add_alert_to_ui(self, alert):
        # Map severity to tags
        severity = alert.get('severity', 'Info').lower()
        # Normalize severity
        severity_tag = severity if severity in ['info','low','medium','high','critical'] else 'info'
        self.alerts_treeview.insert(
            "", tk.END,
            values=(alert.get("timestamp", "N/A"), alert.get("type", "Unknown"), alert.get("severity", "Info"),
                    alert.get("source", "N/A"), alert.get("category", "N/A"), alert.get("description", "N/A")),
            tags=(severity_tag,)
        )

    def setup_alerts_tab(self, parent_frame):
        # --- Alerts Dashboard UI ---
        alerts_label = ttk.Label(parent_frame, text="Detected Alerts:")
        alerts_label.pack(anchor=tk.W, pady=(0, 5))
               
        # Frame for Treeview and scrollbar
        alerts_tree_frame = ttk.Frame(parent_frame)
        alerts_tree_frame.pack(fill=tk.BOTH, expand=True)

        alerts_scrollbar_y = ttk.Scrollbar(alerts_tree_frame, orient="vertical")
        alerts_scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)
        alerts_scrollbar_x = ttk.Scrollbar(alerts_tree_frame, orient="horizontal")
        alerts_scrollbar_x.pack(side=tk.BOTTOM, fill=tk.X)


        self.alerts_treeview = ttk.Treeview(
            alerts_tree_frame,
            columns=("Timestamp", "Type", "Severity", "Source", "Category", "Description"),
            show="headings",
            yscrollcommand=alerts_scrollbar_y.set,
            xscrollcommand=alerts_scrollbar_x.set
        )
        self.alerts_treeview.pack(fill=tk.BOTH, expand=True)

        alerts_scrollbar_y.config(command=self.alerts_treeview.yview)
        alerts_scrollbar_x.config(command=self.alerts_treeview.xview)

        # Define column headings and widths
        self.alerts_treeview.heading("Timestamp", text="Timestamp")
        self.alerts_treeview.heading("Type", text="Type")
        self.alerts_treeview.heading("Severity", text="Severity")
        self.alerts_treeview.heading("Source", text="Source")
        self.alerts_treeview.heading("Category", text="Category")
        self.alerts_treeview.heading("Description", text="Description")

        self.alerts_treeview.column("Timestamp", width=150, stretch=tk.NO)
        self.alerts_treeview.column("Type", width=100, stretch=tk.NO)
        self.alerts_treeview.column("Severity", width=80, stretch=tk.NO)
        self.alerts_treeview.column("Source", width=150, stretch=tk.NO)
        self.alerts_treeview.column("Category", width=100, stretch=tk.NO)
        self.alerts_treeview.column("Description", width=400, stretch=tk.YES) # Let description take remaining space

        self.alerts_treeview.bind('<Double-1>', self.show_alert_details)
        self.alerts_treeview.tag_configure('info', foreground='black')
        self.alerts_treeview.tag_configure('low', foreground='blue')
        self.alerts_treeview.tag_configure('medium', foreground='orange')
        self.alerts_treeview.tag_configure('high', foreground='red')
        self.alerts_treeview.tag_configure('critical', background='darkred', foreground='white')
        self.alerts_treeview.bind('<Double-1>', self.show_alert_details)

        # Add an Export button
        export_button_frame = ttk.Frame(parent_frame)
        export_button_frame.pack(pady=5)

        ttk.Button(export_button_frame, text="Export Alerts (CSV)", command=self.export_alerts_to_csv).pack()


        # Add context menu later for actions like 'Block IP', 'Terminate Process' etc.

    # --- Export Functionality ---
    def export_alerts_to_csv(self):
        """Exports the current list of alerts to a CSV file."""
        if not self.alerts:
            messagebox.showinfo("Export Info", "No alerts to export.")
            return

        # Ask the user for a filename and location to save the file
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            title="Save Alerts as CSV"
        )

        if not filename:
            # User cancelled the dialog
            self.log("Alert export cancelled by user.")
            return

        try:
            # Define the order of columns for the CSV
            fieldnames = ["timestamp", "type", "severity", "source", "category", "description"]

            with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                # Write the header row
                writer.writeheader()

                # Write the alert data
                for alert in self.alerts:
                    # Ensure all fields are present in the dictionary for DictWriter
                    # and handle potential missing keys gracefully (DictWriter does this,
                    # but explicitly setting defaults is safer if needed later)
                    writer.writerow(alert)

            self.log(f"Alerts successfully exported to {filename}")
            messagebox.showinfo("Export Success", f"Alerts successfully exported to:\n{filename}")

        except Exception as e:
            self.log(f"Error exporting alerts to CSV: {e}")
            messagebox.showerror("Export Error", f"An error occurred while exporting alerts:\n{e}")


    # --- Configuration Loading/Saving ---
    def load_config(self):
        """Loads configuration from config.json."""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, "r") as f:
                    config = json.load(f)
                # Merge loaded config with defaults to handle missing keys
                return {**DEFAULT_CONFIG, **config}
            else:
                self.log(f"Config file '{CONFIG_FILE}' not found. Using defaults.")
                return DEFAULT_CONFIG
        except Exception as e:
            self.log(f"Error loading config: {e}. Using defaults.")
            return DEFAULT_CONFIG

    def save_config(self):
        """Saves current configuration to config.json."""
        try:
            # Ensure the config dictionary is up-to-date before saving
            # (Values from UI variables should be transferred before calling this)
            with open(CONFIG_FILE, "w") as f:
                json.dump(self.config, f, indent=4)
            self.log(f"Configuration saved to {CONFIG_FILE}.")
        except Exception as e:
            self.log(f"Error saving config: {e}")

    # --- State Loading/Saving ---
    def load_state(self):
        """Loads operational state from state.json."""
        try:
            if os.path.exists(STATE_FILE):
                with open(STATE_FILE, "r") as f:
                    state = json.load(f)
                self.previous_file_hashes = state.get("previous_file_hashes", {})
                self.log_read_positions = state.get("log_read_positions", {})
                self.previous_listening_ports = state.get("previous_listening_ports", {}) # Load listening ports state
                self.log(f"State loaded from {STATE_FILE}.")
            else:
                self.log(f"State file '{STATE_FILE}' not found.")
        except Exception as e:
            self.log(f"Error loading state: {e}.")
            self.previous_file_hashes = {}
            self.log_read_positions = {}
            self.previous_listening_ports = {}

    def save_state(self):
        """Saves current operational state to state.json."""
        try:
            def _stringify_tuple_keys(d):
                """Convert tuple keys in a dict to strings for JSON serialization."""
                if not isinstance(d, dict):
                    return d
                return {str(k): v for k, v in d.items()}

            state = {
                "previous_file_hashes": self.previous_file_hashes,
                "log_read_positions": self.log_read_positions,
                "previous_listening_ports": _stringify_tuple_keys(self.previous_listening_ports)
            }
            with open(STATE_FILE, "w") as f:
                json.dump(state, f, indent=4)
        except Exception as e:
            self.log(f"Error saving state: {e}")
        
    # --- File Integrity Monitoring ---
    # (Existing code seems mostly fine, ensures hashes/positions are removed if files are unmonitored)
    def update_files_listbox(self):
        # Ensure the listbox exists before updating
        if hasattr(self, 'files_listbox'):
            self.files_listbox.delete(0, tk.END)
            for f in self.config.get("monitored_files", []):
                self.files_listbox.insert(tk.END, f)
        else:
             self.log("Warning: Cannot update files listbox, UI not initialized.")


    def browse_file(self):
        path = filedialog.askopenfilename()
        if path and hasattr(self, 'file_path_var'):
            self.file_path_var.set(path)

    def setup_dashboard_tab(self, parent_frame):
        self.fig, self.ax = plt.subplots(figsize=(5,3))
        self.canvas = FigureCanvasTkAgg(self.fig, master=parent_frame)
        self.canvas_widget = self.canvas.get_tk_widget()
        self.canvas_widget.pack(fill=tk.BOTH, expand=True)

        # Data storage
        self.connection_history = collections.deque(maxlen=60)
        self.threat_ip_hits = collections.deque(maxlen=60)
        self.time_stamps = collections.deque(maxlen=60)

        # Add refresh button
        ttk.Button(parent_frame, text="Update Plot", command=self.update_connection_plot).pack(pady=5)
        # Start periodic plot update
        # Store the ID returned by master.after
        self._plot_update_id = self.master.after(10000, self.update_connection_plot_periodically)

    def update_connection_plot(self):
        self.ax.clear()
        # Example: plot number of connections over time
        if self.connection_history:
            self.ax.plot(self.time_stamps, self.connection_history, label='Connections')
            self.ax.set_xlabel('Time')
            self.ax.set_ylabel('Connections')
            self.ax.set_title('Network Connections Over Time')
            self.ax.legend()
            self.fig.autofmt_xdate()
            self.canvas.draw()

    def update_connection_plot_periodically(self):
        # Check if monitoring is still active
        if not self.monitoring_active:
            return

        # Collect data
        now = datetime.datetime.now()
        total_conns = len(psutil.net_connections())
        threat_hits = len(self.threat_ips)

        self.time_stamps.append(now)
        self.connection_history.append(total_conns)
        self.threat_ip_hits.append(threat_hits)

        # Update plot
        self.update_connection_plot()

        # Schedule next update
        # Store the ID of the next scheduled call
        self._plot_update_id = self.master.after(10000, self.update_connection_plot_periodically)

    def add_monitored_file(self):
        # Ensure UI elements exist
        if not hasattr(self, 'file_path_var') or not hasattr(self, 'files_listbox'):
             messagebox.showerror("UI Error", "File Monitoring UI not initialized.")
             return

        path = self.file_path_var.get().strip()
        if os.path.exists(path):
            if path not in self.config["monitored_files"]:
                self.config["monitored_files"].append(path)
                self.update_files_listbox()
                self.save_config()
                self.log(f"Added '{path}' to monitored files.")
                # Initialize state for new file
                self.previous_file_hashes[path] = calculate_file_hash(path)
                try:
                    self.log_read_positions[path] = os.path.getsize(path)
                except:
                    self.log_read_positions[path] = 0
                self.save_state()
            else:
                self.log(f"'{path}' is already monitored.")
        else:
            self.log(f"Invalid file path: '{path}'")
            messagebox.showwarning("Input Error", f"Invalid file path: '{path}'")

    def setup_process_tree(self, parent_frame):
        # Placeholder: Use a Treeview or Canvas to draw process hierarchy
        self.proc_tree = ttk.Treeview(parent_frame)
        self.proc_tree.pack(fill=tk.BOTH, expand=True)
        self.refresh_process_tree()

    def refresh_process_tree(self):
        self.proc_tree.delete(*self.proc_tree.get_children())
        # Build process tree
        pid_map = {}
        for proc in psutil.process_iter(['pid', 'ppid', 'name']):
            pid_map[proc.info['pid']] = proc.info

        # Build hierarchy
        tree_nodes = {}
        for pid, info in pid_map.items():
            parent_pid = info['ppid']
            node_text = f"{info['name']} (PID {pid})"
            if parent_pid in tree_nodes:
                parent_node = tree_nodes[parent_pid]
                node_id = self.proc_tree.insert(parent_node, tk.END, text=node_text)
            else:
                node_id = self.proc_tree.insert('', tk.END, text=node_text)
            tree_nodes[pid] = node_id

    def show_alert(self, alert_type, description, severity="Info", source="N/A", category="N/A"):
        alert = {
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": alert_type,
            "description": description,
            "severity": severity,
            "source": source,
            "category": category
        }
        self.alert_queue.put(alert)
        # Play sound for high/critical severity
        #if severity in ["High", "Critical"]:
            #self.play_alert_sound()

    def play_alert_sound(self):
        # Beep sound
        try:
            # Windows
            winsound.Beep(1000, 500)
        except:
            # Cross-platform fallback
            print('\a')  # Terminal bell

    def remove_selected_file(self):
        # Ensure UI elements exist
        if not hasattr(self, 'files_listbox'):
             messagebox.showerror("UI Error", "File Monitoring UI not initialized.")
             return

        sel = self.files_listbox.curselection()
        if sel:
            path = self.files_listbox.get(sel[0])
            if path in self.config["monitored_files"]:
                if messagebox.askyesno("Remove File", f"Are you sure you want to stop monitoring:\n'{path}'?"):
                    self.config["monitored_files"].remove(path)
                    self.update_files_listbox()
                    self.save_config()
                    self.log(f"Removed '{path}' from monitored files.")
                    # Remove state for the file
                    self.previous_file_hashes.pop(path, None)
                    self.log_read_positions.pop(path, None)
                    self.save_state()
        else:
             messagebox.showinfo("Selection Error", "Please select a file to remove.")


    def clear_monitored_files(self):
        # Ensure UI elements exist
        if not hasattr(self, 'files_listbox'):
             messagebox.showerror("UI Error", "File Monitoring UI not initialized.")
             return

        if messagebox.askyesno("Clear Files", "Are you sure you want to stop monitoring all files?"):
            self.config["monitored_files"] = []
            self.update_files_listbox()
            self.save_config()
            self.previous_file_hashes = {}
            self.log_read_positions = {}
            self.save_state()
            self.log("Cleared all monitored files.")


    def check_file_integrity(self):
        """Checks the integrity of monitored files."""
        # Ensure files that are no longer monitored are removed from state
        monitored_files_set = set(self.config.get("monitored_files", []))
        keys_to_remove = [f for f in self.previous_file_hashes.keys() if f not in monitored_files_set]
        for f in keys_to_remove:
            self.previous_file_hashes.pop(f, None)
            # Although log_read_positions is for logs, it's good practice to clean up if a file is treated as both
            self.log_read_positions.pop(f, None)

        current_hashes = {}
        files_to_check = list(monitored_files_set) # Work with a list for iteration
        self.log(f"Checking integrity of {len(files_to_check)} files...")

        for f in files_to_check:
            current_hash = calculate_file_hash(f)
            if current_hash is None:
                 if f in self.previous_file_hashes:
                     # File was monitored and hashed before, but is now missing or inaccessible
                     self.log(f"[!] Monitored file missing or inaccessible: {f}")
                     self.show_alert("File Integrity", f"File missing or inaccessible: {f}", severity="High", source=f, category="File Monitoring")
                 # If it was never hashed, just log the issue
                 elif os.path.exists(f):
                     self.log(f"Could not hash file: {f} (Permission denied or error)")
                 else:
                      self.log(f"File not found: {f}")
                 # Do NOT add None hash to current_hashes if it was previously valid
                 # Keep the old hash in the new dict if we can't calculate a new one
                 if f in self.previous_file_hashes:
                      current_hashes[f] = self.previous_file_hashes[f]
                 continue # Skip comparison if no current hash

            current_hashes[f] = current_hash
            prev_hash = self.previous_file_hashes.get(f)

            if prev_hash is None:
                # First time monitoring this file
                self.log(f"Now monitoring file: {f}")
            elif prev_hash != current_hash:
                # File has been modified
                self.log(f"[!] File modified: {f}")
                self.show_alert("File Integrity", f"File modified: {f}", severity="High", source=f, category="File Monitoring")

        self.previous_file_hashes = current_hashes # Update state with current successful hashes
        self.save_state()


    # --- Log Analysis ---
    def analyze_logs(self):
        """Analyzes specified log files for keywords."""
        paths = self.config.get("log_paths", [])
        keywords = self.config.get("log_keywords", [])
        if not paths or not keywords:
            return

        expanded_files = set()
        for pattern in paths:
            # Expand patterns like *.log
            expanded_files.update(glob.glob(pattern))

        # Clean up state for logs that are no longer monitored
        keys_to_remove = [f for f in self.log_read_positions.keys() if f not in expanded_files]
        for f in keys_to_remove:
            self.log_read_positions.pop(f, None)

        self.log(f"Analyzing {len(expanded_files)} log files for keywords...")
        keywords_lower = [k.lower() for k in keywords] # Optimize keyword matching

        for logf in expanded_files:
            if not os.path.exists(logf):
                 self.log(f"Log file not found: {logf}")
                 continue

            try:
                last_pos = self.log_read_positions.get(logf, 0)
                size = os.path.getsize(logf)

                if size < last_pos:
                    self.log(f"Log file truncated or rotated: {logf}. Reading from start.")
                    last_pos = 0 # Reset position if file is smaller

                if size == last_pos:
                    continue # No new content

                # Use 'rb' mode to handle potential issues with text modes and seek/tell across platforms
                with open(logf, "rb") as f:
                    f.seek(last_pos)
                    # Read new content from the current position
                    # Need to decode bytes to string for keyword matching
                    new_bytes = f.read()
                    current_pos = f.tell() # Get the position after reading bytes

                    try:
                         # Attempt to decode the bytes to text
                         new_content = new_bytes.decode(errors='ignore')
                    except Exception as e:
                         self.log(f"Error decoding new content from log {logf}: {e}")
                         # Don't process this chunk, but update the position
                         self.log_read_positions[logf] = current_pos
                         continue


                    # Analyze new content line by line
                    for line in new_content.splitlines():
                         line_lower = line.lower()
                         for k in keywords_lower:
                             if k in line_lower:
                                 msg = f"Log: {logf}: {line.strip()}"
                                 self.log(f"[!] {msg}")
                                 self.show_alert("Log Alert", msg, severity="Medium", source=logf, category="Log Monitoring")
                                 break # Found a keyword, move to next line

                    # Update the read position ONLY if we successfully read and decoded
                    self.log_read_positions[logf] = current_pos

            except Exception as e:
                self.log(f"Error reading log file {logf}: {e}")
                # Don't update position if there was an error

        self.save_state() # Save positions after checking all logs


    # --- Signature Management ---
    def load_signatures(self):
        """Loads signatures from the signatures file (now including category/severity/is_regex)."""
        self.signatures.clear() # Clear existing signatures
        filename = self.config.get("signatures_file", "signatures.txt")
        try:
            if os.path.exists(filename):
                with open(filename, "r") as f:
                    for line in f:
                         line = line.strip()
                         if line and not line.startswith('#'): # Ignore empty lines and comments
                             try:
                                 sig_data = json.loads(line)
                                 # Validate basic structure
                                 if isinstance(sig_data, dict) and "pattern" in sig_data:
                                     # Ensure category, severity, and is_regex have defaults if missing
                                     sig_data.setdefault("category", "Network")
                                     sig_data.setdefault("severity", "Medium")
                                     sig_data.setdefault("is_regex", False) # Default to not regex

                                     # Ensure severity is valid
                                     if sig_data["severity"] not in SEVERITY_LEVELS:
                                         sig_data["severity"] = "Medium" # Default invalid severity
                                         self.log(f"Warning: Invalid severity for signature '{sig_data['pattern']}'. Set to Medium.")

                                     # Basic regex pattern validation on load (optional but good practice)
                                     if sig_data["is_regex"]:
                                         try:
                                             re.compile(sig_data["pattern"])
                                         except re.error:
                                             self.log(f"Warning: Invalid regex pattern in signatures file: '{sig_data['pattern']}'. Skipping.")
                                             continue # Skip this signature if regex is invalid

                                     self.signatures.append(sig_data)
                                 else:
                                     self.log(f"Warning: Skipping invalid signature line: {line}")
                             except json.JSONDecodeError:
                                 self.log(f"Warning: Skipping invalid JSON signature line: {line}")

                if hasattr(self, 'sig_listbox'):
                     self.refresh_signatures_listbox()

                self.log(f"Loaded {len(self.signatures)} signatures.")
            else:
                self.log(f"Signatures file '{filename}' not found. No signatures loaded.")
                # Optionally, save a default empty file with the regex preference included
                self.save_signatures() # Creates the file if it doesn't exist

        except Exception as e:
            self.log(f"Error loading signatures from {filename}: {e}")


    def save_signatures(self):
        """Saves current signatures to the signatures file in JSON Lines format."""
        filename = self.config.get("signatures_file", "signatures.txt")
        try:
            with open(filename, "w") as f:
                for sig_data in self.signatures:
                    # Ensure required keys are present before saving
                    sig_to_save = {
                        "pattern": sig_data.get("pattern", ""),
                        "category": sig_data.get("category", "Network"),
                        "severity": sig_data.get("severity", "Medium"),
                        "is_regex": sig_data.get("is_regex", False) # Include is_regex
                    }
                    # Basic validation before saving
                    if sig_to_save["pattern"].strip():
                        f.write(json.dumps(sig_to_save) + "\n")
                    else:
                         self.log(f"Warning: Skipping saving an empty signature pattern.")

            # The global signature_regex config can potentially be removed now
            # self.config["signature_regex"] = self.signature_regex_var.get()
            # self.save_config() # Save config if other settings are changed in this tab

            self.log(f"Signatures saved to {filename}.")


        except Exception as e:
            self.log(f"Error saving signatures to {filename}: {e}")
            messagebox.showerror("Signature Save Error", f"Error saving signatures: {e}")

    def refresh_signatures_listbox(self):
        """Refreshes the signatures listbox display."""
        # Ensure the listbox exists before trying to refresh
        if hasattr(self, 'sig_listbox'):
            self.sig_listbox.delete(0, tk.END)
            for sig_data in self.signatures:
                display_text = f"[{sig_data.get('severity', 'Unknown')}] ({sig_data.get('category', 'Unknown')}): {sig_data.get('pattern', 'Invalid Signature')}"
                self.sig_listbox.insert(tk.END, display_text)
        else:
             self.log("Warning: Cannot refresh signatures listbox, UI not initialized.")


    def load_selected_signature(self, event):
        """Loads the selected signature details into the entry fields for editing."""
        # Ensure the listbox exists
        if not hasattr(self, 'sig_listbox'):
             return # UI not ready

        sel_indices = self.sig_listbox.curselection()
        if not sel_indices:
            # Clear fields if nothing is selected or selection is cleared
            # Ensure UI elements exist
            if hasattr(self, 'sig_pattern_var'):
                self.sig_pattern_var.set("")
                self.sig_category_var.set("Network")
                self.sig_severity_var.set("Medium")
            return

        index = sel_indices[0]
        if 0 <= index < len(self.signatures):
            sig_data = self.signatures[index]
            # Ensure UI elements exist
            if hasattr(self, 'sig_pattern_var'):
                self.sig_pattern_var.set(sig_data.get("pattern", ""))
                self.sig_category_var.set(sig_data.get("category", "Network"))
                self.sig_severity_var.set(sig_data.get("severity", "Medium")) # Set dropdown value
        else:
            # This shouldn't happen if selection is valid, but as a safeguard
            self.log(f"Error: Invalid index {index} selected in signatures list.")
            if hasattr(self, 'sig_pattern_var'):
                self.sig_pattern_var.set("")
                self.sig_category_var.set("Network")
                self.sig_severity_var.set("Medium")


    def add_signature_from_ui(self):
        pattern = self.sig_pattern_var.get().strip()
        category = self.sig_category_var.get().strip() or "Network"
        severity = self.sig_severity_var.get().strip()
        is_regex = self.signature_regex_var.get()

        # Validate severity
        if severity not in SEVERITY_LEVELS:
            messagebox.showwarning("Input Error", f"Invalid severity '{severity}'.")
            return

        # Validate pattern
        if not pattern:
            messagebox.showwarning("Input Error", "Signature pattern cannot be empty.")
            return

        # If regex is enabled, verify pattern validity
        if is_regex:
            try:
                re.compile(pattern)
            except re.error as e:
                messagebox.showerror("Regex Error", f"Invalid regex pattern: {e}")
                return

        # Check for duplicate pattern
        if any(s['pattern'] == pattern and s['is_regex'] == is_regex for s in self.signatures):
            messagebox.showinfo("Duplicate", f"Pattern already exists.")
            return

        new_sig = {
            "pattern": pattern,
            "category": category,
            "severity": severity,
            "is_regex": is_regex
        }
        self.signatures.append(new_sig)
        self.save_signatures()
        self.refresh_signatures_listbox()
        self.log(f"Added signature: [{severity}] ({category}): '{pattern}'")
        # Clear fields
        self.sig_pattern_var.set("")
        self.sig_category_var.set("Network")
        self.sig_severity_var.set("Medium")
        # Ensure listbox exists before clearing selection
        if hasattr(self, 'sig_listbox'):
             self.sig_listbox.selection_clear(0, tk.END) # Clear listbox selection

    def edit_signature_from_ui(self):
        """Edits the selected signature using values from UI entry fields."""
        # Ensure UI elements exist
        if not hasattr(self, 'sig_listbox') or not hasattr(self, 'sig_pattern_var'):
             messagebox.showerror("UI Error", "Signature UI not initialized.")
             return

        sel_indices = self.sig_listbox.curselection()
        if not sel_indices:
            messagebox.showwarning("Selection Error", "Please select a signature to edit.")
            return

        index = sel_indices[0]
        if not (0 <= index < len(self.signatures)):
             self.log(f"Error: Invalid index {index} selected for editing.")
             messagebox.showerror("Edit Error", "Invalid signature selected.")
             return

        pattern = self.sig_pattern_var.get().strip()
        category = self.sig_category_var.get().strip() or "Network"
        severity = self.sig_severity_var.get().strip()

        if not pattern:
            messagebox.showwarning("Input Error", "Signature pattern cannot be empty.")
            return
        if severity not in SEVERITY_LEVELS:
             messagebox.showwarning("Input Error", f"Invalid severity '{severity}'. Please select from the dropdown.")
             return

        original_sig = self.signatures[index]
        updated_sig = {"pattern": pattern, "category": category, "severity": severity}

        if original_sig == updated_sig:
             self.log("No changes detected for signature.")
             # Clear fields and selection even if no changes were made
             self.sig_pattern_var.set("")
             self.sig_category_var.set("Network")
             self.sig_severity_var.set("Medium")
             self.sig_listbox.selection_clear(0, tk.END)
             return # No changes made

        # Optional: Check if the new pattern duplicates another existing signature (excluding the one being edited)
        if any(i != index and s['pattern'] == pattern for i, s in enumerate(self.signatures)):
             messagebox.showinfo("Duplicate", f"Signature pattern '{pattern}' already exists for another signature.")
             return

        self.signatures[index] = updated_sig
        self.save_signatures() # Save after editing
        self.refresh_signatures_listbox() # Refresh UI after saving
        self.log(f"Edited signature: {original_sig.get('pattern', 'N/A')} -> '{pattern}'")

        # Clear fields after editing
        self.sig_pattern_var.set("")
        self.sig_category_var.set("Network")
        self.sig_severity_var.set("Medium")
        self.sig_listbox.selection_clear(0, tk.END) # Clear listbox selection


    def delete_signature_from_ui(self):
        """Deletes the selected signature."""
        # Ensure UI elements exist
        if not hasattr(self, 'sig_listbox'):
             messagebox.showerror("UI Error", "Signature UI not initialized.")
             return

        sel_indices = self.sig_listbox.curselection()
        if not sel_indices:
            messagebox.showwarning("Selection Error", "Please select a signature to delete.")
            return

        index = sel_indices[0]
        if not (0 <= index < len(self.signatures)):
             self.log(f"Error: Invalid index {index} selected for deletion.")
             messagebox.showerror("Delete Error", "Invalid signature selected.")
             return

        sig_to_delete = self.signatures[index]
        display_text = f"[{sig_to_delete.get('severity', 'Unknown')}] ({sig_to_delete.get('category', 'Unknown')}): {sig_to_delete.get('pattern', 'Invalid Signature')}"

        if messagebox.askyesno("Delete Signature", f"Are you sure you want to delete signature:\n'{display_text}'?"):
            del self.signatures[index]
            self.save_signatures() # Save after deleting
            self.refresh_signatures_listbox() # Refresh UI after saving
            self.log(f"Deleted signature: '{display_text}'")

            # Clear entry fields if the deleted signature was loaded
            # Ensure UI elements exist
            if hasattr(self, 'sig_pattern_var'):
                self.sig_pattern_var.set("")
                self.sig_category_var.set("Network")
                self.sig_severity_var.set("Medium")
            self.sig_listbox.selection_clear(0, tk.END) # Clear listbox selection


    # --- Threat Intelligence Feed ---
    def schedule_threat_feed_update(self):
        """Schedules the IP threat feed update."""
        # Only schedule if monitoring is active and interval > 0
        interval_ms = self.config.get("threat_feed_update_hours", 1) * 60 * 60 * 1000
        if interval_ms > 0:
             threading.Thread(target=self.fetch_threat_feed, daemon=True).start()
             if self.monitoring_active:
                 self.master.after(interval_ms, self.schedule_threat_feed_update)
             else:
                  self.log("IP threat feed scheduled but monitoring is stopped. Will run on next start.")

        elif interval_ms <= 0:
             self.log("IP threat feed updates are disabled (interval set to 0).")


    def fetch_threat_feed(self):
        """Fetches the IP threat feed."""
        url = self.config.get("threat_feed_url")
        if not url:
            self.log("IP Threat feed URL not configured.")
            self.show_alert("Configuration Issue", "IP Threat feed URL not configured.", severity="Low", category="Configuration")
            return

        try:
            self.log(f"Fetching IP threat feed from {url}...")
            response = requests.get(url, timeout=20) # Increased timeout slightly
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)

            new_threat_ips = set()
            for line in response.text.splitlines():
                line = line.strip()
                # Simple parsing for IP lists (ignore comments and empty lines)
                if line and not line.startswith('#') and not line.startswith(';'):
                     # Basic check if it looks like an IP (can be improved)
                     if '.' in line or ':' in line: # IPv4 or IPv6
                         new_threat_ips.add(line)

            # Atomically replace the threat_ips set
            self.threat_ips = new_threat_ips
            self.log(f"IP Threat intelligence feed updated successfully. Loaded {len(self.threat_ips)} entries.")

        except requests.exceptions.RequestException as e:
            self.log(f"Failed to fetch IP threat feed from {url}: {e}")
            self.show_alert("Threat Feed Error", f"Failed to fetch IP threat feed from {url}: {e}", severity="Medium", source=url, category="Threat Intel")
        except Exception as e:
            self.log(f"Error processing IP threat feed from {url}: {e}")
            self.show_alert("Threat Feed Error", f"Error processing IP threat feed from {url}: {e}", severity="Medium", source=url, category="Threat Intel")


    def schedule_domain_threat_feed_update(self):
        """Schedules the Domain threat feed update."""
         # Only schedule if monitoring is active and interval > 0
        interval_ms = self.config.get("domain_threat_feed_update_hours", 6) * 60 * 60 * 1000
        if interval_ms > 0:
            threading.Thread(target=self.fetch_domain_threat_feed, daemon=True).start()
            if self.monitoring_active:
                self.master.after(interval_ms, self.schedule_domain_threat_feed_update)
            else:
                 self.log("Domain threat feed scheduled but monitoring is stopped. Will run on next start.")

        elif interval_ms <= 0:
             self.log("Domain threat feed updates are disabled (interval set to 0).")


    def fetch_domain_threat_feed(self):
        """Fetches the Domain threat feed."""
        url = self.config.get("domain_threat_feed_url")
        if not url:
            self.log("Domain Threat feed URL not configured.")
            self.show_alert("Configuration Issue", "Domain Threat feed URL not configured.", severity="Low", category="Configuration")
            return

        try:
            self.log(f"Fetching Domain threat feed from {url}...")
            response = requests.get(url, timeout=20)
            response.raise_for_status()

            new_threat_domains = set()
            for line in response.text.splitlines():
                line = line.strip()
                # Simple parsing for hosts file like formats (IP address followed by domain)
                # Or just lines of domains
                if line and not line.startswith('#') and not line.startswith(';'):
                    parts = line.split()
                    if len(parts) > 1:
                        # Assume format like IP domain (e.g., 0.0.0.0 badsite.com)
                        domain = parts[1]
                        if domain and not domain.startswith('#'):
                            new_threat_domains.add(domain)
                    elif len(parts) == 1:
                         # Assume format is just domain name per line
                         domain = parts[0]
                         if domain and not domain.startswith('#'):
                             new_threat_domains.add(domain)


            # Atomically replace the threat_domains set
            self.threat_domains = new_threat_domains
            self.log(f"Domain Threat intelligence feed updated successfully. Loaded {len(self.threat_domains)} entries.")

        except requests.exceptions.RequestException as e:
            self.log(f"Failed to fetch Domain threat feed from {url}: {e}")
            self.show_alert("Threat Feed Error", f"Failed to fetch Domain threat feed from {url}: {e}", severity="Medium", source=url, category="Threat Intel")
        except Exception as e:
            self.log(f"Error processing Domain threat feed from {url}: {e}")
            self.show_alert("Threat Feed Error", f"Error processing Domain threat feed from {url}: {e}", severity="Medium", source=url, category="Threat Intel")


    # --- Network Monitoring ---
    def network_sniffer(self):
        """Starts the network sniffing thread."""
        self.log("Network sniffer started...")
        iface = self.config.get("network_interface")
        bpf_filter = self.config.get("bpf_filter", "tcp or udp") # Get filter from config

        def stop_sniff_filter(packet):
            """Filter function to stop sniffing when the stop event is set."""
            return self.stop_event.is_set()

        try:
            # Sniff for TCP and UDP (for DNS) packets
            # Using L3RawSocket might be needed on some systems, but keep simple for now
            sniff(filter=bpf_filter, prn=self.packet_callback, store=False, iface=iface, stop_filter=stop_sniff_filter, timeout=1)
            self.log("Network sniffer stopped.")
        except PermissionError:
            self.log("Sniffer Permission Error: Running Scapy often requires administrator/root privileges.")
            self.show_alert("Sniffer Permission Error", "Running Scapy often requires administrator/root privileges.", severity="Critical", category="System Issue")
        except Scapy_Exception as e:
             self.log(f"Scapy sniffer error: {e}")
             self.show_alert("Sniffer Error", f"Scapy sniffer encountered an error: {e}\nCheck interface or privileges.", severity="High", category="System Issue")
        except Exception as e:
            self.log(f"Sniffer error: {e}")
            self.show_alert("Sniffer Error", f"Network sniffer encountered an unexpected error: {e}", severity="High", category="System Issue")


    def packet_callback(self, packet):
        """Processes each sniffed packet."""
        if self.stop_event.is_set():
            return True # Signal sniff to stop

        # Wrap packet processing in try/except to prevent one bad packet from crashing the sniffer thread
        try:
            self.track_tcp_session(packet)
            self.check_for_signatures(packet)
            self.check_for_threat_ips(packet) # Renamed to be explicit
            self.check_dns_request(packet) # Check for blacklisted domains in DNS

            # Simple connection count (can be part of anomaly detection later)
            # if IP in packet:
            #    src_ip = packet[IP].src
                # This is a simple counter, consider removing or enhancing for baselining
                # self.connection_counts[src_ip] += 1
        except Exception as e:
             self.log(f"Error processing packet: {e} Packet summary: {packet.summary()}")
             # Avoid showing alerts for every packet error


    def track_tcp_session(self, packet):
        """Tracks TCP session states (existing functionality)."""
        # Ensure IP and TCP layers exist before accessing them
        if IP in packet and TCP in packet:
            try:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                flags = packet[TCP].flags

                # Ensure consistent key regardless of direction
                key = tuple(sorted(((src_ip, sport), (dst_ip, dport))))

                state = self.tcp_sessions.get(key, {"state": "NONE", "packets": 0, "bytes": 0})

                # Update state based on TCP flags
                # This logic can be complex, keeping it basic for now
                if flags == "S":
                    if state["state"] == "NONE":
                        state["state"] = "SYN_SENT"
                    elif state["state"] == "SYN_RECEIVED":
                         state["state"] = "ESTABLISHED" # SYN-ACK received, session established
                elif flags == "SA":
                    if state["state"] == "SYN_SENT":
                        state["state"] = "ESTABLISHED"
                elif flags == "A":
                     # Acknowledgment - indicates ongoing communication
                     if state["state"] in ["SYN_SENT", "SYN_RECEIVED", "ESTABLISHED"]:
                          state["state"] = "ESTABLISHED"
                elif flags == "F" or flags == "R":
                    # FIN or RST - session is closing or reset
                    state["state"] = "CLOSED"
                    # Optional: Remove closed sessions after a delay

                state["packets"] += 1
                state["bytes"] += len(packet)
                self.tcp_sessions[key] = state

                # Clean up old closed sessions periodically (not implemented here)
            except Exception as e:
                 self.log(f"Error tracking TCP session: {e} Packet summary: {packet.summary()}")


    def check_for_signatures(self, packet):
        """Checks packet payload against defined signatures."""
        if IP in packet and TCP in packet:
            payload_bytes = bytes(packet[TCP].payload)
            if not payload_bytes:
                return

            try:
                payload_str = payload_bytes.decode(errors='ignore')
            except Exception as e:
                 self.log(f"Error decoding packet payload for signature check: {e} Packet summary: {packet.summary()}")
                 payload_str = ""

            if not payload_str:
                return

            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            conn_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"

            for sig_data in self.signatures:
                pattern = sig_data.get("pattern")
                category = sig_data.get("category", "Network")
                severity = sig_data.get("severity", "Medium")
                is_regex = sig_data.get("is_regex", False) # Get the flag for this signature

                if not pattern: continue

                try:
                    match = False
                    if is_regex:
                        try:
                            # Use re.search for finding the pattern anywhere in the string
                            if re.search(pattern, payload_str):
                                match = True
                        except re.error:
                            # This case should ideally be caught on load/save, but as a safeguard
                            self.log(f"Invalid regex signature pattern encountered during check: '{pattern}'")
                            continue

                    else:
                        if pattern in payload_str:
                            match = True

                    if match:
                        sig_type = "Regex" if is_regex else "Text"
                        description = f"{sig_type} signature '{pattern}' matched in TCP payload ({conn_info})"
                        self.log(f"[!] Signature match: {description}")
                        self.show_alert(
                            "Signature Match",
                            description,
                            severity=severity,
                            source=conn_info,
                            category=category
                        )
                        # Optionally break here if you only want one signature match per packet
                        # break

                except Exception as e:
                    self.log(f"Error checking signature '{pattern}': {e} Packet summary: {packet.summary()}")


    def check_for_threat_ips(self, packet):
        """Checks packet source/destination IPs against the threat IP feed."""
        # Ensure IP layer exists
        if IP in packet:
            try:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst

                # Get protocol and port information if TCP or UDP layers exist
                protocol_name = "IP" # Default to IP
                src_port = "N/A"
                dst_port = "N/A"

                if TCP in packet:
                    protocol_name = "TCP"
                    src_port = packet[TCP].sport
                    dst_port = packet[TCP].dport
                elif UDP in packet:
                    protocol_name = "UDP"
                    src_port = packet[UDP].sport
                    dst_port = packet[UDP].dport

                # Create a connection string with protocol and ports
                conn_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol_name})"


                alerted = False # Flag to avoid double alerting for the same packet

                # Check Source IP
                if src_ip in self.threat_ips:
                    description = f"Connection from known threat IP: {src_ip}. Details: {conn_info}"
                    self.log(f"[!] {description}")
                    self.show_alert(
                        "Threat IP Detected",
                        description,
                        severity="High",
                        source=src_ip, # Keep source as IP for easy filtering in alerts
                        category="Threat Intel"
                    )
                    alerted = True

                # Check Destination IP (only if source wasn't a threat IP to avoid duplicate alerts for the same packet)
                if not alerted and dst_ip in self.threat_ips:
                    description = f"Connection to known threat IP: {dst_ip}. Details: {conn_info}"
                    self.log(f"[!] {description}")
                    self.show_alert(
                        "Threat IP Detected",
                        description,
                        severity="High",
                        source=dst_ip, # Keep source as IP for easy filtering in alerts
                        category="Threat Intel"
                    )
                    # alerted = True # No need to set here as we are done checking this packet


            except Exception as e:
                self.log(f"Error checking threat IPs: {e} Packet summary: {packet.summary()}")

    # Note: If you implemented the combined system/network check using psutil,
    # the threat IP check for *processes* communicating with threat IPs should be done there.
    # That check can include process PID/Name in the alert, providing even more context.
    # The sniffer-based check here is for any packet on the wire matching a threat IP,
    # potentially before a process connection is fully established or visible via psutil.


    def check_dns_request(self, packet):
        """Checks DNS queries against the threat domain feed."""
        # Ensure UDP and DNS layers exist
        if UDP in packet and packet.haslayer(DNS):
            dns_layer = packet[DNS]
            # Check if it's a query (qd field exists) and not a response
            if dns_layer.qd and dns_layer.qr == 0: # qr=0 for query
                try:
                    # Multiple queries are possible, iterate through them
                    for i in range(dns_layer.qdcount):
                        query_name_bytes = dns_layer.qd[i].qname
                        try:
                            # qname includes a trailing dot, remove it
                            queried_domain = query_name_bytes.decode('utf-8').rstrip('.')
                        except Exception as e:
                            self.log(f"Could not decode DNS query name: {query_name_bytes}. Error: {e}")
                            continue # Skip if decoding fails

                        # Check against the threat domain list
                        if queried_domain and queried_domain in self.threat_domains:
                            src_ip = packet[IP].src if IP in packet else "N/A"
                            description = f"Query for known malicious domain: {queried_domain}"
                            self.log(f"[!] {description} from {src_ip}")
                            self.show_alert(
                                "Malicious Domain Query",
                                description,
                                severity="High",
                                source=src_ip,
                                category="Threat Intel"
                            )
                        # Optional: Check for subdomains? 'badsite.com' in 'sub.badsite.com'?
                except Exception as e:
                     self.log(f"Error processing DNS queries in packet: {e} Packet summary: {packet.summary()}")


    def perform_system_and_network_checks(self):
        """
        Combines process iteration and checks for connections,
        listening ports, and suspicious processes.
        Runs periodically in a worker thread.
        """
        self.log("Performing system and network checks...")
        current_threat_ips = self.threat_ips # Get a reference
        # current_threat_domains = self.threat_domains # Domains checked in packet_callback


        # Example list of suspicious names/keywords (can be moved to config)
        suspicious_keywords_lower = [k.lower() for k in ["malware", "trojan", "RAT", "backdoor", "exploit", "powershell -enc"]]

        current_listening_ports = {} # {(ip, port, proto): process_info_dict}
        total_connections = 0 # To count total connections for anomaly check

        try:
            # Iterate through processes once
            # REMOVE 'connections' from attrs list here
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']): # Added 'exe' attribute
                 # Add inner try-except to handle errors for individual processes
                try:
                    # Get basic process info
                    info = proc.as_dict(attrs=['pid', 'name', 'cmdline', 'exe']) # Get 'exe' path
                    cmdline = ' '.join(info.get('cmdline') or [])
                    name = info.get('name', '')
                    pid = info.get('pid')
                    exe_path = info.get('exe') # Get executable path

                    process_suspicious_flag = False

                    # Check process name or cmdline for suspicious keywords
                    cmdline_lower = cmdline.lower()
                    name_lower = name.lower()
                    if any(k in cmdline_lower or k in name_lower for k in suspicious_keywords_lower):
                        description = f"Suspicious process name or command line: {name} (PID: {pid}, Cmd: '{cmdline}')"
                        self.log(f"[!] {description}")
                        self.show_alert(
                            "Suspicious Process",
                            description,
                            severity="High",
                            source=f"PID: {pid}",
                            category="System Activity"
                        )
                        process_suspicious_flag = True


                    # Check executable path
                    if exe_path:
                        try:
                            exe_dir = os.path.dirname(exe_path)
                            exe_dir_normalized = os.path.normcase(exe_dir)

                            # Check if the executable directory is NOT in the trusted list
                            if not any(exe_dir_normalized.startswith(td) for td in trusted_dirs_normalized):
                                description = f"Process '{name}' (PID: {pid}) running from unusual directory: '{exe_dir}'"
                                self.log(f"[!] {description}")
                                self.show_alert(
                                    "Process Unusual Location",
                                    description,
                                    severity="Medium", # Adjust severity as needed
                                    source=f"PID: {pid}",
                                    category="System Activity"
                                )
                                process_suspicious_flag = True # Mark as suspicious


                        except Exception as path_e:
                            self.log(f"Error checking executable path for PID {pid}: {path_e}")
                            pass # Continue even if path check fails


                    # Now, get the connections for THIS process using the method
                    # Wrap this call in its own specific exception handling
                    try:
                        net_connections = proc.connections(kind='inet') # Call the method here
                        total_connections += len(connections) # Add to total count

                        for conn in net_connections:
                            # Ensure laddr and raddr exist and are not None
                            if conn.laddr:
                                # local_addr = f"{conn.laddr.ip}:{conn.laddr.port}"
                                status = conn.status

                                # Check for listening ports (This was moved to check_listening_ports for better separation)
                                # if status == 'LISTEN':
                                #     ... listening port logic ...


                                # Check remote address against threat IPs (only if remote address exists)
                                # Threat IP check is also done by the sniffer, but this links it to a process
                                if hasattr(conn, 'raddr') and conn.raddr is not None:
                                   remote_ip = conn.raddr.ip
                                   if remote_ip != "N/A" and remote_ip in current_threat_ips:
                                       description = f"Process {name} (PID: {pid}) connects to threat IP: {remote_ip}"
                                       self.log(f"[!] {description}")
                                       self.show_alert(
                                           "Process Communicating with Threat IP",
                                           description,
                                           severity="Critical", # Critical severity for C2 communication
                                           source=f"PID: {pid} -> {remote_ip}",
                                           category="Threat Intel"
                                       )
                                       process_suspicious_flag = True
                                       break # Found a threat IP connection within this process

                    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, AttributeError) as conn_e:
                         # Catch errors specific to fetching/iterating connections for this process
                         self.log(f"Error fetching connections for PID {pid}: {conn_e}")
                         pass # Skip connection check for this process


                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as proc_e: # Catch specific process errors
                    # Log these specific process errors
                    pid_str = str(proc.pid) if hasattr(proc, 'pid') else 'N/A'
                    self.log(f"Skipping process PID {pid_str} due to access/existence issue: {proc_e}")
                    continue # Skip processes we can't access or that died
                except Exception as e:
                    # Catch any other unexpected errors during initial process info gathering
                    pid_str = str(proc.pid) if hasattr(proc, 'pid') else 'N/A'
                    self.log(f"Error inspecting process (PID: {pid_str}): {e}")
                    # Avoid showing too many alerts for process errors, maybe just log


            # After iterating through all processes, perform checks that need the aggregated data

            # Check for high overall connection count
            conn_threshold = self.config.get("connection_anomaly_threshold", 200)
            if total_connections > conn_threshold:
                self.log(f"[!] High system connection count: {total_connections}")
                self.show_alert("Network Anomaly", f"High system connection count: {total_connections} (threshold {conn_threshold})", severity="Medium", category="Network Anomaly")


            # Compare current listening ports with previous ones (This logic was moved to check_listening_ports)
            # ... listening port comparison logic removed ...

            # Update the state with the current listening ports (This is now in check_listening_ports)
            # self.previous_listening_ports = current_listening_ports
            # self.save_state() # Save state after updating listening ports


        except psutil.AccessDenied:
            self.log("Access denied to list system processes (psutil). Cannot perform system/network checks.")
            self.show_alert("Access Denied", "Cannot perform system/network checks. Run with sufficient privileges.", severity="Medium", category="System Issue")
        except Exception as e:
            self.log(f"Error during combined system/network checks: {e}")
            self.show_alert("System/Network Check Error", f"An error occurred during combined checks: {e}", severity="High", category="System Issue")


            # After iterating through all processes, perform checks that need the aggregated data

            # Check for high overall connection count
            conn_threshold = self.config.get("connection_anomaly_threshold", 200)
            if total_connections > conn_threshold:
                self.log(f"[!] High system connection count: {total_connections}")
                self.show_alert("Network Anomaly", f"High system connection count: {total_connections} (threshold {conn_threshold})", severity="Medium", category="Network Anomaly")


            # Compare current listening ports with previous ones
            previously_listening = set(self.previous_listening_ports.keys())
            currently_listening = set(current_listening_ports.keys())

            newly_listening_ports = currently_listening - previously_listening

            if newly_listening_ports:
                for port_key in newly_listening_ports:
                    ip, port, proto_name = port_key
                    proc_info = current_listening_ports.get(port_key, {})
                    description = f"New listening port detected: {ip}:{port}/{proto_name} by PID {proc_info.get('pid', 'N/A')} ({proc_info.get('name', 'N/A')})"
                    self.log(f"[!] {description}")
                    self.show_alert(
                        "New Listening Port",
                        description,
                        severity="Medium", # Severity could be adjusted
                        source=f"{ip}:{port}/{proto_name}",
                        category="System Activity"
                    )

            # Update the state with the current listening ports
            self.previous_listening_ports = current_listening_ports
            self.save_state() # Save state after updating listening ports


        except psutil.AccessDenied:
            self.log("Access denied to list system processes (psutil). Cannot perform system/network checks.")
            self.show_alert("Access Denied", "Cannot perform system/network checks. Run with sufficient privileges.", severity="Medium", category="System Issue")
        except Exception as e:
            self.log(f"Error during combined system/network checks: {e}")
            self.show_alert("System/Network Check Error", f"An error occurred during combined checks: {e}", severity="High", category="System Issue")


    # --- System Monitoring ---

    # Add the check_firewall method here (from the previous response)
    def check_firewall(self):
        self.log("Checking firewall status...")
        try:
            if sys.platform.startswith('win'):
                # Use CREATE_NO_WINDOW instead of HIDE_WINDOW
                # Use shell=True for 'sc query' to work reliably in some environments
                result = subprocess.run(['sc', 'query', 'MpsSvc'], capture_output=True, text=True, creationflags=CREATE_NO_WINDOW, shell=True)
                if "STATE" in result.stdout and "RUNNING" in result.stdout:
                    self.log("Windows Firewall service is running.")
                else:
                    self.log("Windows Firewall service might not be running.")
                    self.show_alert("Firewall Status", "Windows Firewall may not be running.", severity="Medium", category="System Check")
            elif sys.platform.startswith('linux'):
                try:
                    # Use sudo -n to avoid password prompt if configured in sudoers
                    # Add shell=True for sudo to work reliably in some environments
                    subprocess.run(['sudo', '-n', 'iptables', '-L'], check=True, capture_output=True, text=True, timeout=5, shell=True)
                    self.log("iptables rules checked.")
                except (subprocess.CalledProcessError, FileNotFoundError):
                    try:
                        subprocess.run(['sudo', '-n', 'ufw', 'status'], check=True, capture_output=True, text=True, timeout=5, shell=True)
                        self.log("UFW status checked.")
                    except (subprocess.CalledProcessError, FileNotFoundError):
                        self.log("Neither iptables nor ufw available.")
                        self.show_alert("Firewall Status", "Cannot check iptables or UFW.", severity="Low", category="System Check")
                except subprocess.TimeoutExpired:
                    self.log("Linux firewall check timed out.")
                    self.show_alert("Firewall Status", "Linux firewall check timed out.", severity="Low", category="System Check")
            elif sys.platform == 'darwin':
                try:
                    # Use sudo -n for pfctl
                    # Add shell=True for sudo to work reliably in some environments
                    subprocess.run(['sudo', '-n', 'pfctl', '-s', 'rules'], check=True, capture_output=True, text=True, timeout=5, shell=True)
                    self.log("pfctl rules checked.")
                except (subprocess.CalledProcessError, FileNotFoundError):
                    self.log("pfctl not available.")
                    self.show_alert("Firewall Status", "Cannot check pfctl.", severity="Low", category="System Check")
                except subprocess.TimeoutExpired:
                    self.log("macOS firewall check timed out.")
                    self.show_alert("Firewall Status", "macOS firewall check timed out.", severity="Low", category="System Check")
            else:
                self.log(f"Firewall check not implemented for OS: {sys.platform}")
                self.show_alert("Firewall Status", f"Firewall check not implemented for OS: {sys.platform}", severity="Low", category="System Check")
        except Exception as e:
            # Catch any other unexpected errors during firewall check
            self.log(f"Firewall check error: {e}")
            self.show_alert("Firewall Check Error", f"An error occurred during firewall check: {e}", severity="High", category="System Issue")


    def monitor_connections(self):
        """Monitors active network connections using psutil."""
        self.log("Checking network connections...")
        try:
            conns = psutil.net_connections(kind='inet')
            total_connections = len(conns)
            conn_threshold = self.config.get("connection_anomaly_threshold", 200)

            if total_connections > conn_threshold:
                self.log(f"[!] High system connection count: {total_connections}")
                self.show_alert("Network Anomaly", f"High system connection count: {total_connections} (threshold {conn_threshold})", severity="Medium", category="Network Anomaly")

            current_threat_ips = self.threat_ips

            for c in conns:
                local_addr_str = "N/A"
                remote_addr_str = "N/A"
                remote_ip = None # Initialize remote_ip

                # Safely get local address info
                # Check if laddr exists and is a tuple with at least 2 elements (ip, port)
                if c.laddr and isinstance(c.laddr, tuple) and len(c.laddr) >= 2:
                    local_ip = c.laddr[0]
                    local_port = c.laddr[1]
                    local_addr_str = f"{local_ip}:{local_port}"
                elif c.laddr:
                     # Log if laddr is not the expected tuple format
                     self.log(f"Warning: Unexpected laddr format for connection: {c.laddr} (Type: {type(c.laddr)})")


                # Safely get remote address info and check against threat IPs
                # Check if raddr exists and is a tuple with at least 2 elements (ip, port)
                if c.raddr and isinstance(c.raddr, tuple) and len(c.raddr) >= 2:
                    remote_ip = c.raddr[0]
                    remote_port = c.raddr[1]
                    remote_addr_str = f"{remote_ip}:{remote_port}"

                    if remote_ip != "N/A" and remote_ip in current_threat_ips:
                        # Use the safely constructed address strings
                        description = f"Suspicious connection {local_addr_str} -> {remote_addr_str} ({c.status})"
                        self.log(f"[!] {description}")
                        self.show_alert("Suspicious Connection", description, severity="High", source=f"{local_addr_str} -> {remote_addr_str}", category="Threat Intel")
                elif c.raddr:
                     # Log if raddr is not the expected tuple format
                     self.log(f"Warning: Unexpected raddr format for connection: {c.raddr} (Type: {type(c.raddr)})")


        except psutil.AccessDenied:
            self.log("Access denied to list network connections (psutil).")
            self.show_alert("Access Denied", "Cannot list system network connections. Run with sufficient privileges.", severity="Medium", category="System Issue")
        except Exception as e:
             self.log(f"Error monitoring connections: {e}") # Keep this general catch-all
             self.show_alert("System Monitoring Error", f"Error monitoring network connections: {e}", severity="Medium", category="System Issue")


    def check_listening_ports(self):
        """Checks for new or unexpected listening ports."""
        self.log("Checking listening ports...")
        current_listening_ports = {} # {(ip, port, proto): process_info_dict}

        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
                try:
                    pinfo = proc.as_dict(attrs=['pid', 'name', 'cmdline'])
                    pinfo['cmdline'] = ' '.join(pinfo.get('cmdline') or [])
                    pinfo['name'] = pinfo.get('name', '')
                    pid = pinfo['pid']

                    net_connections = proc.net_connections(kind='inet')

                    for conn in net_connections:
                        # Ensure conn.laddr exists and is the expected tuple format
                        if conn.status == 'LISTEN' and conn.laddr and isinstance(conn.laddr, tuple) and len(conn.laddr) >= 2:
                            ip = conn.laddr[0]
                            port = conn.laddr[1]
                            proto = conn.type # socket.SOCK_STREAM (TCP) or socket.SOCK_DGRAM (UDP)
                            import socket # Imported here locally for this function
                            proto_name = "TCP" if proto == socket.SOCK_STREAM else ("UDP" if proto == socket.SOCK_DGRAM else str(proto))

                            port_key = (ip, port, proto_name)

                            current_listening_ports[port_key] = {
                                "pid": pid,
                                "name": pinfo['name'],
                                "cmdline": pinfo['cmdline']
                            }
                        elif conn.status == 'LISTEN' and conn.laddr:
                            # Log if laddr is not the expected tuple format for a listening connection
                            self.log(f"Warning: Unexpected laddr format for listening connection: {conn.laddr} (Type: {type(conn.laddr)}) on process PID {pid}")


                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as proc_e:
                    pid_str = str(proc.pid) if hasattr(proc, 'pid') else 'N/A'
                    self.log(f"Skipping process PID {pid_str} due to access/existence issue: {proc_e}")
                    continue
                except Exception as e:
                    pid_str = str(proc.pid) if hasattr(proc, 'pid') else 'N/A'
                    self.log(f"Error inspecting process (PID: {pid_str}): {e}")


            previously_listening = set(self.previous_listening_ports.keys())
            currently_listening = set(current_listening_ports.keys())

            newly_listening_ports = currently_listening - previously_listening

            if newly_listening_ports:
                for port_key in newly_listening_ports:
                    ip, port, proto_name = port_key
                    proc_info = current_listening_ports.get(port_key, {})
                    description = f"New listening port detected: {ip}:{port}/{proto_name} by PID {proc_info.get('pid', 'N/A')} ({proc_info.get('name', 'N/A')})"
                    self.log(f"[!] {description}")
                    self.show_alert(
                        "New Listening Port",
                        description,
                        severity="Medium",
                        source=f"{ip}:{port}/{proto_name}",
                        category="System Activity"
                    )

            self.previous_listening_ports = current_listening_ports
            self.save_state()

        except psutil.AccessDenied:
            self.log("Access denied to list system processes for connection check (psutil). Cannot check listening ports.")
            self.show_alert("Access Denied", "Cannot check listening ports. Run with sufficient privileges.", severity="Medium", category="System Issue")
        except Exception as e:
            self.log(f"Error checking listening ports: {e}")
            self.show_alert("System Monitoring Error", f"Error checking listening ports: {e}", severity="Medium", category="System Issue")


            # Compare current listening ports with previous ones
            previously_listening = set(self.previous_listening_ports.keys())
            currently_listening = set(current_listening_ports.keys())

            newly_listening_ports = currently_listening - previously_listening

            if newly_listening_ports:
                for port_key in newly_listening_ports:
                    ip, port, proto_name = port_key
                    proc_info = current_listening_ports.get(port_key, {})
                    description = f"New listening port detected: {ip}:{port}/{proto_name} by PID {proc_info.get('pid', 'N/A')} ({proc_info.get('name', 'N/A')})"
                    self.log(f"[!] {description}")
                    self.show_alert(
                        "New Listening Port",
                        description,
                        severity="Medium", # Severity could be adjusted
                        source=f"{ip}:{port}/{proto_name}",
                        category="System Activity"
                    )

            # Update the state with the current listening ports
            self.previous_listening_ports = current_listening_ports
            self.save_state()

        except psutil.AccessDenied:
            self.log("Access denied to list system processes for connection check (psutil). Cannot check listening ports.")
            self.show_alert("Access Denied", "Cannot check listening ports. Run with sufficient privileges.", severity="Medium", category="System Issue")
        except Exception as e:
            self.log(f"Error checking listening ports: {e}")
            self.show_alert("System Monitoring Error", f"Error checking listening ports: {e}", severity="Medium", category="System Issue")


            # Compare current listening ports with previous ones
            previously_listening = set(self.previous_listening_ports.keys())
            currently_listening = set(current_listening_ports.keys())

            newly_listening_ports = currently_listening - previously_listening

            if newly_listening_ports:
                for port_key in newly_listening_ports:
                    ip, port, proto_name = port_key
                    proc_info = current_listening_ports.get(port_key, {})
                    description = f"New listening port detected: {ip}:{port}/{proto_name} by PID {proc_info.get('pid', 'N/A')} ({proc_info.get('name', 'N/A')})"
                    self.log(f"[!] {description}")
                    self.show_alert(
                        "New Listening Port",
                        description,
                        severity="Medium", # Severity could be adjusted
                        source=f"{ip}:{port}/{proto_name}",
                        category="System Activity"
                    )

            # Update the state with the current listening ports
            self.previous_listening_ports = current_listening_ports
            self.save_state()

        except psutil.AccessDenied:
            self.log("Access denied to list system processes for connection check (psutil). Cannot check listening ports.")
            self.show_alert("Access Denied", "Cannot check listening ports. Run with sufficient privileges.", severity="Medium", category="System Issue")
        except Exception as e:
            self.log(f"Error checking listening ports: {e}")
            self.show_alert("System Monitoring Error", f"Error checking listening ports: {e}", severity="Medium", category="System Issue")


    def monitor_system_activity(self):
        """Monitors running processes for suspicious activity using psutil."""
        self.log("Checking system activity...")

        suspicious_keywords_lower = [k.lower() for k in ["malware", "trojan", "RAT", "backdoor", "exploit", "powershell -enc"]]
        trusted_dirs = self.config.get("trusted_process_dirs", [])  # Get trusted directories from config
        trusted_dirs_normalized = [os.path.normcase(d) for d in trusted_dirs]

        try:
            current_threat_ips = self.threat_ips

            for p in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                try:
                    info = p.as_dict(attrs=['pid', 'name', 'cmdline', 'exe'])
                    cmdline = ' '.join(info.get('cmdline') or [])
                    name = info.get('name', '')
                    pid = info.get('pid')
                    exe_path = info.get('exe')

                    process_suspicious_flag = False

                    # Check process name or cmdline for suspicious keywords
                    cmdline_lower = cmdline.lower()
                    name_lower = name.lower()
                    if any(k in cmdline_lower or k in name_lower for k in suspicious_keywords_lower):
                        description = f"Suspicious process name or command line: {name} (PID: {pid}, Cmd: '{cmdline}')"
                        self.log(f"[!] {description}")
                        self.show_alert(
                            "Suspicious Process",
                            description,
                            severity="High",
                            source=f"PID: {pid}",
                            category="System Activity"
                        )
                        process_suspicious_flag = True

                    # Check executable path
                    if exe_path:
                        try:
                            exe_dir = os.path.dirname(exe_path)
                            exe_dir_normalized = os.path.normcase(exe_dir)

                            if not any(exe_dir_normalized.startswith(td) for td in trusted_dirs_normalized):
                                description = f"Process '{name}' (PID: {pid}) running from unusual directory: '{exe_dir}'"
                                self.log(f"[!] {description}")
                                self.show_alert(
                                    "Process Unusual Location",
                                    description,
                                    severity="Medium",
                                    source=f"PID: {pid}",
                                    category="System Activity"
                                )
                                process_suspicious_flag = True
                        except Exception as path_e:
                            self.log(f"Error checking executable path for PID {pid}: {path_e}")
                            pass  # Continue even if path check fails

                    # Check connections for this process against threat IPs
                    if not process_suspicious_flag:
                        try:
                            connections = p.net_connections(kind='inet')
                            for c in connections:
                                if hasattr(c, 'raddr') and c.raddr is not None:
                                    remote_ip = c.raddr[0]
                                    if remote_ip in current_threat_ips:
                                        description = f"Process {name} (PID: {pid}) connects to threat IP: {remote_ip}"
                                        self.log(f"[!] {description}")
                                        self.show_alert(
                                            "Process Communicating with Threat IP",
                                            description,
                                            severity="Critical",
                                            source=f"PID: {pid} -> {remote_ip}",
                                            category="Threat Intel"
                                        )
                                        process_suspicious_flag = True
                                        break
                        except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                            continue  # Can't access connections for this process
                        except Exception as e:
                            self.log(f"Error getting connections for PID {pid}: {e}")

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                except Exception as e:
                    pid_str = str(p.pid) if hasattr(p, 'pid') else 'N/A'
                    self.log(f"Error inspecting process (PID: {pid_str}): {e}")

        except psutil.AccessDenied:
            self.log("Access denied to monitor system processes.")
            self.show_alert("Access Denied", "Cannot monitor system processes. Run with sufficient privileges.", severity="Medium", category="System Issue")
        except Exception as e:
            self.log(f"Error in system activity monitoring: {e}")
            self.show_alert("System Monitoring Error", f"Error in system activity monitoring: {e}", severity="High", category="System Issue")

       
  
    # --- Core Monitoring Control ---
    def start_monitoring(self):
        """Starts all monitoring threads and periodic tasks."""
        if self.monitoring_active:
            self.log("Monitoring is already active.")
            return

        self._plot_update_id = self.master.after(10000, 
    self.update_connection_plot_periodically)
        # Optionally, call immediately to show initial data
        self.update_connection_plot()

        self.monitoring_active = True
        self.stop_event.clear() # Clear event to allow threads to run
        self.btn_start.config(state=tk.DISABLED)
        self.btn_stop.config(state=tk.NORMAL)
        self.log("Starting monitoring processes...")

        # Save current config/state before starting
        self.save_config_from_ui() # Save latest UI config
        self.save_state() # Save current state

        # Load latest signatures and threat feeds before starting
        # load_signatures is now called after setup_ui
        # self.load_signatures() # Called in __init__ after setup_ui
        self.fetch_threat_feed() # Initial fetch (scheduled updates run later)
        self.fetch_domain_threat_feed()

        # Clear previous alerts and listening ports state on a fresh start
        self.alerts.clear()
        # Ensure treeview exists before clearing
        if hasattr(self, 'alerts_treeview'):
            self.alerts_treeview.delete(*self.alerts_treeview.get_children())
        self.previous_listening_ports = {} # Reset this state on start

        # Start sniffer thread (daemon=True allows it to exit with the main app)
        sniffer_thread = threading.Thread(target=self.network_sniffer, daemon=True)
        self.monitoring_threads.append(sniffer_thread)
        sniffer_thread.start()
        self.log("Network sniffer thread started.")

        # Start periodic tasks loop in the main thread
        self.log("Scheduling periodic monitoring tasks...")
        # Call periodic_tasks once immediately, then it reschedules itself
        self.periodic_tasks()


    def stop_monitoring(self):
        """Stops all monitoring threads and periodic tasks."""
        if not self.monitoring_active:
            self.log("Monitoring is already stopped.")
            return

        self.monitoring_active = False # Set this first
        self.stop_event.set() # Signal threads to stop
        self.btn_start.config(state=tk.NORMAL)
        self.btn_stop.config(state=tk.DISABLED)
        self.log("Stopping monitoring processes. Please wait...")

        # Cancel periodic tasks
        if hasattr(self, '_periodic_tasks_id') and self._periodic_tasks_id is not None:
            try:
                self.master.after_cancel(self._periodic_tasks_id)
            except tk.TclError:
                pass
            self._periodic_tasks_id = None

        # No need to explicitly cancel _process_queues_id here,
        # as the check `if not self.monitoring_active:` at the top of `process_queues`
        # will cause it to stop rescheduling itself once the queue is empty after stopping.
        # Explicitly cancelling here could interrupt flushing the last messages.

        if hasattr(self, '_plot_update_id') and self._plot_update_id is not None:
             try:
                self.master.after_cancel(self._plot_update_id)
             except tk.TclError:
                 pass
             self._plot_update_id = None


        # Wait briefly for daemon threads to finish (optional)
        # They should exit when the main thread exits, but joining can ensure cleanup
        for t in self.monitoring_threads:
            if t.is_alive():
                try:
                    t.join(timeout=1) # Wait max 1 second per thread
                except RuntimeError:
                     # Handle case where thread is the current thread or not started correctly
                     pass
                except Exception as e:
                     self.log(f"Error joining thread: {e}")


        self.monitoring_threads = [] # Clear the list

        # Save state on stop
        self.save_state()
        self.log("Monitoring stopped.")

    def on_closing(self):
        """Handles application closing."""
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.log("Shutting down application...")
            self.stop_monitoring() # Stop monitoring first
            # State and config are saved by stop_monitoring and save_config_from_ui

            # At this point, stop_monitoring should have cancelled periodic and plot updates.
            # The process_queues should stop naturally once monitoring_active is False
            # and its queue is empty. We can add extra checks here for safety, but
            # the primary cancellation is in stop_monitoring.

            # Example extra safety checks for after_cancel (less critical now):
            # if hasattr(self, 'periodic_task_id') and self.periodic_task_id is not None:
            #      try: self.master.after_cancel(self.periodic_task_id) except tk.TclError: pass
            # if hasattr(self, '_process_queues_id') and self._process_queues_id is not None:
            #      try: self.master.after_cancel(self._process_queues_id) except tk.TclError: pass
            # if hasattr(self, '_plot_update_id') and self._plot_update_id is not None:
            #      try: self.master.after_cancel(self._plot_update_id) except tk.TclError: pass


            # Give a moment for queues to *potentially* finish processing last messages
            # This is not guaranteed, as after_cancel might have already happened.
            time.sleep(0.1)


            self.master.destroy() # Close the main window
            os._exit(0)

    def start_periodic_tasks(self):
        interval = self.config.get("monitoring_interval_sec", 10)
        self._periodic_tasks_id = self.master.after(interval * 1000, self.periodic_tasks)

    def stop_periodic_tasks(self):
        if hasattr(self, '_periodic_tasks_id') and self._periodic_tasks_id is not None:
            try:
                self.master.after_cancel(self._periodic_tasks_id)
            except tk.TclError:
                pass
            self._periodic_tasks_id = None

    def periodic_tasks(self):
        """Runs periodic monitoring checks."""
        # Retrieve the interval at the beginning of the function
        interval = self.config.get("monitoring_interval_sec", 10)

        if not self.monitoring_active:
            self.log("Periodic tasks loop stopped.")
            # Clear the scheduled task ID if monitoring is no longer active
            self._periodic_tasks_id = None
            return

    # Run checks that don't require continuous, high-frequency operation
    # Add try/except around each periodic task call to prevent one task from stopping others
        try:
            self.check_firewall()
        except Exception as e:
            self.log(f"Error in check_firewall periodic task: {e}")
            self.show_alert("Periodic Task Error", f"Error in firewall check: {e}", severity="High", category="System Issue")

        try:
            self.check_file_integrity()
        except Exception as e:
            self.log(f"Error in check_file_integrity periodic task: {e}")
            self.show_alert("Periodic Task Error", f"Error in file integrity check: {e}", severity="High", category="System Issue")

        try:
            self.monitor_connections() # Includes high connection count and psutil threat IP checks
        except Exception as e:
            self.log(f"Error in monitor_connections periodic task: {e}")
            self.show_alert("Periodic Task Error", f"Error in network connection monitoring: {e}", severity="High", category="System Issue")

        try:
            self.analyze_logs()
        except Exception as e:
            self.log(f"Error in analyze_logs periodic task: {e}")
            self.show_alert("Periodic Task Error", f"Error in log analysis: {e}", severity="High", category="System Issue")

        try:
            self.monitor_system_activity() # Includes process name/cmdline and psutil process threat IP checks
        except Exception as e:
            self.log(f"Error in monitor_system_activity periodic task: {e}")
            self.show_alert("Periodic Task Error", f"Error in system activity monitoring: {e}", severity="High", category="System Issue")

        try:
            self.check_listening_ports() # New check for listening ports
        except Exception as e:
            self.log(f"Error in check_listening_ports periodic task: {e}")
            self.show_alert("Periodic Task Error", f"Error in listening ports check: {e}", severity="High", category="System Issue")


    # Schedule the next run of periodic tasks ONLY if monitoring is still active and interval is positive
        if interval > 0 and self.monitoring_active:
           self._periodic_tasks_id = self.master.after(interval * 1000, self.periodic_tasks)
        elif interval <= 0:
           self.log("Periodic tasks are disabled (monitoring_interval_sec set to 0).")
    # If monitoring_active is False, the loop naturally stops because of the check at the beginning


             
# Helper mapping for IP protocol numbers to names (incomplete list)
IPPROTO = {
    1: 'ICMP',
    6: 'TCP',
    17: 'UDP',
    47: 'GRE',
    50: 'ESP',
    51: 'AH',
    89: 'OSPF',
    132: 'SCTP'
}
# Import socket for protocol constants
import socket


# Run the app
if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("1800x800")  # or any size you prefer
    # Apply a modern theme (optional, requires ttk)
    try:
        style = ttk.Style()
        style.theme_use('clam') # or 'alt', 'default', 'classic'
    except:
        pass # Ignore if themes are not available

    app = SecurityMonitorApp(root)
    root.mainloop()
