"""Main GUI application for Andy VulnScanner."""

import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from typing import Optional

from vulnscanner.reports.exporter import ReportExporter
from vulnscanner.scanner.port_scanner import PortResult, PortScanner, ScanResult
from vulnscanner.scanner.vuln_checker import VulnChecker, Vulnerability
from vulnscanner.scanner.advanced_scanner import AdvancedScanner, AdvFinding, AdvScanResult
from vulnscanner.scanner.extra_scanner import ExtraFinding, ExtraScanner, ExtraScanResult
from vulnscanner.scanner.web_scanner import WebFinding, WebScanner, WebScanResult


class DarkTheme:
    """Dark theme colors inspired by Kali Linux."""

    BG_PRIMARY = "#0d1117"
    BG_SECONDARY = "#161b22"
    BG_TERTIARY = "#21262d"
    BG_INPUT = "#0d1117"
    FG_PRIMARY = "#c9d1d9"
    FG_SECONDARY = "#8b949e"
    FG_ACCENT = "#58a6ff"
    FG_SUCCESS = "#3fb950"
    FG_WARNING = "#d29922"
    FG_ERROR = "#f85149"
    FG_CRITICAL = "#ff0000"
    BORDER = "#30363d"
    HIGHLIGHT = "#1f6feb"
    BUTTON_BG = "#238636"
    BUTTON_FG = "#ffffff"
    BUTTON_HOVER = "#2ea043"
    STOP_BG = "#da3633"
    STOP_HOVER = "#f85149"


class AndyVulnScanner(tk.Tk):
    """Main application window for the vulnerability scanner."""

    def __init__(self):
        super().__init__()

        self.title("Andy VulnScanner v1.0")
        self.geometry("1100x750")
        self.minsize(900, 600)
        self.configure(bg=DarkTheme.BG_PRIMARY)

        # State
        self.scanner = PortScanner()
        self.vuln_checker = VulnChecker()
        self.web_scanner = WebScanner()
        self.adv_scanner = AdvancedScanner()
        self.extra_scanner = ExtraScanner()
        self.current_result: Optional[ScanResult] = None
        self.current_vulns: list[Vulnerability] = []
        self.current_web_result: Optional[WebScanResult] = None
        self.current_adv_result: Optional[AdvScanResult] = None
        self.current_extra_result: Optional[ExtraScanResult] = None
        self.is_scanning = False
        self.scan_thread: Optional[threading.Thread] = None

        # Configure styles
        self._configure_styles()

        # Build the UI
        self._build_header()
        self._build_config_panel()
        self._build_notebook()
        self._build_status_bar()

        # Center the window
        self.update_idletasks()
        x = (self.winfo_screenwidth() - self.winfo_reqwidth()) // 2
        y = (self.winfo_screenheight() - self.winfo_reqheight()) // 2
        self.geometry(f"+{x}+{y}")

        # Handle close
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_styles(self):
        """Configure ttk styles for dark theme."""
        style = ttk.Style(self)
        style.theme_use("clam")

        # General
        style.configure(".", background=DarkTheme.BG_PRIMARY,
                         foreground=DarkTheme.FG_PRIMARY,
                         fieldbackground=DarkTheme.BG_INPUT,
                         bordercolor=DarkTheme.BORDER,
                         darkcolor=DarkTheme.BG_SECONDARY,
                         lightcolor=DarkTheme.BG_TERTIARY,
                         troughcolor=DarkTheme.BG_SECONDARY,
                         selectbackground=DarkTheme.HIGHLIGHT,
                         selectforeground="#ffffff",
                         focuscolor=DarkTheme.FG_ACCENT)

        # Frames
        style.configure("TFrame", background=DarkTheme.BG_PRIMARY)
        style.configure("Card.TFrame", background=DarkTheme.BG_SECONDARY,
                         relief="flat")

        # Labels
        style.configure("TLabel", background=DarkTheme.BG_PRIMARY,
                         foreground=DarkTheme.FG_PRIMARY, font=("Segoe UI", 10))
        style.configure("Header.TLabel", font=("Segoe UI", 22, "bold"),
                         foreground=DarkTheme.FG_ACCENT,
                         background=DarkTheme.BG_SECONDARY)
        style.configure("SubHeader.TLabel", font=("Segoe UI", 10),
                         foreground=DarkTheme.FG_SECONDARY,
                         background=DarkTheme.BG_SECONDARY)
        style.configure("Card.TLabel", background=DarkTheme.BG_SECONDARY)
        style.configure("Status.TLabel", background=DarkTheme.BG_TERTIARY,
                         foreground=DarkTheme.FG_SECONDARY, font=("Segoe UI", 9))

        # Entry
        style.configure("TEntry", fieldbackground=DarkTheme.BG_INPUT,
                         foreground=DarkTheme.FG_PRIMARY,
                         insertcolor=DarkTheme.FG_PRIMARY,
                         bordercolor=DarkTheme.BORDER)

        # Combobox
        style.configure("TCombobox", fieldbackground=DarkTheme.BG_INPUT,
                         foreground=DarkTheme.FG_PRIMARY,
                         selectbackground=DarkTheme.HIGHLIGHT,
                         selectforeground="#ffffff")
        style.map("TCombobox",
                  fieldbackground=[("readonly", DarkTheme.BG_INPUT)],
                  foreground=[("readonly", DarkTheme.FG_PRIMARY)])

        # Buttons
        style.configure("Scan.TButton", font=("Segoe UI", 11, "bold"),
                         background=DarkTheme.BUTTON_BG,
                         foreground=DarkTheme.BUTTON_FG,
                         padding=(20, 8))
        style.map("Scan.TButton",
                  background=[("active", DarkTheme.BUTTON_HOVER),
                              ("disabled", DarkTheme.BG_TERTIARY)])

        style.configure("Stop.TButton", font=("Segoe UI", 11, "bold"),
                         background=DarkTheme.STOP_BG,
                         foreground="#ffffff",
                         padding=(20, 8))
        style.map("Stop.TButton",
                  background=[("active", DarkTheme.STOP_HOVER)])

        style.configure("Export.TButton", font=("Segoe UI", 9),
                         background=DarkTheme.BG_TERTIARY,
                         foreground=DarkTheme.FG_PRIMARY,
                         padding=(12, 5))
        style.map("Export.TButton",
                  background=[("active", DarkTheme.BORDER)])

        # Notebook
        style.configure("TNotebook", background=DarkTheme.BG_PRIMARY,
                         bordercolor=DarkTheme.BORDER)
        style.configure("TNotebook.Tab", background=DarkTheme.BG_TERTIARY,
                         foreground=DarkTheme.FG_SECONDARY,
                         padding=(15, 6),
                         font=("Segoe UI", 10))
        style.map("TNotebook.Tab",
                  background=[("selected", DarkTheme.BG_SECONDARY)],
                  foreground=[("selected", DarkTheme.FG_ACCENT)])

        # Treeview
        style.configure("Treeview",
                         background=DarkTheme.BG_SECONDARY,
                         foreground=DarkTheme.FG_PRIMARY,
                         fieldbackground=DarkTheme.BG_SECONDARY,
                         bordercolor=DarkTheme.BORDER,
                         font=("Consolas", 10),
                         rowheight=28)
        style.configure("Treeview.Heading",
                         background=DarkTheme.BG_TERTIARY,
                         foreground=DarkTheme.FG_PRIMARY,
                         font=("Segoe UI", 10, "bold"))
        style.map("Treeview",
                  background=[("selected", DarkTheme.HIGHLIGHT)],
                  foreground=[("selected", "#ffffff")])

        # Progressbar
        style.configure("Scan.Horizontal.TProgressbar",
                         troughcolor=DarkTheme.BG_TERTIARY,
                         background=DarkTheme.FG_ACCENT,
                         darkcolor=DarkTheme.FG_ACCENT,
                         lightcolor=DarkTheme.FG_ACCENT,
                         bordercolor=DarkTheme.BORDER)

        # Separator
        style.configure("TSeparator", background=DarkTheme.BORDER)

    def _build_header(self):
        """Build the header section."""
        header_frame = ttk.Frame(self, style="Card.TFrame")
        header_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        inner = ttk.Frame(header_frame, style="Card.TFrame")
        inner.pack(fill=tk.X, padx=20, pady=15)

        title_label = ttk.Label(inner, text="Andy VulnScanner",
                                 style="Header.TLabel")
        title_label.pack(side=tk.LEFT)

        subtitle = ttk.Label(inner,
                              text="  Vulnerability Scanner for Kali Linux",
                              style="SubHeader.TLabel")
        subtitle.pack(side=tk.LEFT, padx=(10, 0), pady=(8, 0))

        # Version badge
        ver_frame = tk.Frame(inner, bg=DarkTheme.FG_ACCENT, padx=8, pady=2)
        ver_frame.pack(side=tk.RIGHT)
        tk.Label(ver_frame, text="v1.0", bg=DarkTheme.FG_ACCENT,
                 fg="#ffffff", font=("Segoe UI", 9, "bold")).pack()

    def _build_config_panel(self):
        """Build the scan configuration panel."""
        config_frame = ttk.Frame(self, style="Card.TFrame")
        config_frame.pack(fill=tk.X, padx=10, pady=5)

        inner = ttk.Frame(config_frame, style="Card.TFrame")
        inner.pack(fill=tk.X, padx=20, pady=12)

        # Row 1: Target and Scan Type
        row1 = ttk.Frame(inner, style="Card.TFrame")
        row1.pack(fill=tk.X, pady=(0, 8))

        # Target
        ttk.Label(row1, text="Target:", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.target_entry = ttk.Entry(row1, width=35, font=("Consolas", 11))
        self.target_entry.pack(side=tk.LEFT, padx=(8, 20))
        self.target_entry.insert(0, "127.0.0.1")
        self.target_entry.bind("<Return>", lambda e: self._start_scan())

        # Scan Type
        ttk.Label(row1, text="Scan Type:", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.scan_type_var = tk.StringVar(value="Common Ports")
        self.scan_type_combo = ttk.Combobox(
            row1, textvariable=self.scan_type_var,
            values=["Common Ports", "Full Scan (1-65535)", "Custom Ports"],
            state="readonly", width=22, font=("Segoe UI", 10),
        )
        self.scan_type_combo.pack(side=tk.LEFT, padx=(8, 20))
        self.scan_type_combo.bind("<<ComboboxSelected>>", self._on_scan_type_change)

        # Custom Ports
        ttk.Label(row1, text="Ports:", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.ports_entry = ttk.Entry(row1, width=20, font=("Consolas", 10))
        self.ports_entry.pack(side=tk.LEFT, padx=(8, 0))
        self.ports_entry.insert(0, "80,443,22,21")
        self.ports_entry.configure(state="disabled")

        # Row 2: Timeout, Threads, Buttons
        row2 = ttk.Frame(inner, style="Card.TFrame")
        row2.pack(fill=tk.X)

        # Timeout
        ttk.Label(row2, text="Timeout (s):", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.timeout_var = tk.StringVar(value="1.5")
        timeout_spin = ttk.Entry(row2, textvariable=self.timeout_var,
                                  width=6, font=("Consolas", 10))
        timeout_spin.pack(side=tk.LEFT, padx=(8, 20))

        # Threads
        ttk.Label(row2, text="Threads:", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.threads_var = tk.StringVar(value="100")
        threads_spin = ttk.Entry(row2, textvariable=self.threads_var,
                                  width=6, font=("Consolas", 10))
        threads_spin.pack(side=tk.LEFT, padx=(8, 20))

        # Buttons
        self.scan_button = ttk.Button(row2, text="Start Scan",
                                       style="Scan.TButton",
                                       command=self._start_scan)
        self.scan_button.pack(side=tk.RIGHT, padx=(5, 0))

        self.stop_button = ttk.Button(row2, text="Stop",
                                       style="Stop.TButton",
                                       command=self._stop_scan,
                                       state="disabled")
        self.stop_button.pack(side=tk.RIGHT, padx=(5, 0))

    def _build_notebook(self):
        """Build the results notebook with tabs."""
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Tab 1: Port Results
        self.ports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.ports_frame, text="  Open Ports  ")
        self._build_ports_tab()

        # Tab 2: Vulnerabilities
        self.vulns_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.vulns_frame, text="  Vulnerabilities  ")
        self._build_vulns_tab()

        # Tab 3: Web Scanner
        self.web_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.web_frame, text="  Web Scanner  ")
        self._build_web_tab()

        # Tab 4: Advanced Scanner
        self.adv_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.adv_frame, text="  Advanced Scan  ")
        self._build_adv_tab()

        # Tab 5: Extra Scanner
        self.extra_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.extra_frame, text="  Recon & API  ")
        self._build_extra_tab()

        # Tab 6: Console Log
        self.console_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.console_frame, text="  Console  ")
        self._build_console_tab()

        # Tab 7: Export
        self.export_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.export_frame, text="  Export  ")
        self._build_export_tab()

    def _build_ports_tab(self):
        """Build the ports results treeview."""
        # Summary bar
        self.ports_summary = ttk.Label(
            self.ports_frame, text="No scan performed yet.",
            font=("Segoe UI", 10), foreground=DarkTheme.FG_SECONDARY,
        )
        self.ports_summary.pack(fill=tk.X, padx=10, pady=(10, 5))

        # Treeview
        columns = ("port", "state", "service", "version")
        self.ports_tree = ttk.Treeview(
            self.ports_frame, columns=columns, show="headings", height=15,
        )

        self.ports_tree.heading("port", text="Port")
        self.ports_tree.heading("state", text="State")
        self.ports_tree.heading("service", text="Service")
        self.ports_tree.heading("version", text="Version / Banner")

        self.ports_tree.column("port", width=80, anchor="center")
        self.ports_tree.column("state", width=80, anchor="center")
        self.ports_tree.column("service", width=120, anchor="center")
        self.ports_tree.column("version", width=400)

        # Scrollbar
        scrollbar = ttk.Scrollbar(self.ports_frame, orient=tk.VERTICAL,
                                   command=self.ports_tree.yview)
        self.ports_tree.configure(yscrollcommand=scrollbar.set)

        self.ports_tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10),
                              side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT, pady=(0, 10), padx=(0, 10))

    def _build_vulns_tab(self):
        """Build the vulnerabilities treeview."""
        # Summary bar
        self.vulns_summary_frame = ttk.Frame(self.vulns_frame)
        self.vulns_summary_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        self.vulns_summary = ttk.Label(
            self.vulns_summary_frame, text="No vulnerabilities checked yet.",
            font=("Segoe UI", 10), foreground=DarkTheme.FG_SECONDARY,
        )
        self.vulns_summary.pack(side=tk.LEFT)

        self.risk_label = ttk.Label(
            self.vulns_summary_frame, text="",
            font=("Segoe UI", 10, "bold"),
        )
        self.risk_label.pack(side=tk.RIGHT, padx=10)

        # Treeview
        columns = ("severity", "port", "service", "title", "cve")
        self.vulns_tree = ttk.Treeview(
            self.vulns_frame, columns=columns, show="headings", height=10,
        )

        self.vulns_tree.heading("severity", text="Severity")
        self.vulns_tree.heading("port", text="Port")
        self.vulns_tree.heading("service", text="Service")
        self.vulns_tree.heading("title", text="Vulnerability")
        self.vulns_tree.heading("cve", text="CVE")

        self.vulns_tree.column("severity", width=80, anchor="center")
        self.vulns_tree.column("port", width=60, anchor="center")
        self.vulns_tree.column("service", width=100, anchor="center")
        self.vulns_tree.column("title", width=350)
        self.vulns_tree.column("cve", width=130, anchor="center")

        scrollbar = ttk.Scrollbar(self.vulns_frame, orient=tk.VERTICAL,
                                   command=self.vulns_tree.yview)
        self.vulns_tree.configure(yscrollcommand=scrollbar.set)

        self.vulns_tree.pack(fill=tk.BOTH, expand=True, padx=10, side=tk.LEFT)
        scrollbar.pack(fill=tk.Y, side=tk.RIGHT, padx=(0, 10))

        # Detail panel
        self.vuln_detail = scrolledtext.ScrolledText(
            self.vulns_frame, height=6, wrap=tk.WORD,
            bg=DarkTheme.BG_SECONDARY, fg=DarkTheme.FG_PRIMARY,
            font=("Consolas", 10), insertbackground=DarkTheme.FG_PRIMARY,
            relief="flat", state="disabled",
        )
        self.vuln_detail.pack(fill=tk.X, padx=10, pady=(5, 10), side=tk.BOTTOM)

        # Bind selection
        self.vulns_tree.bind("<<TreeviewSelect>>", self._on_vuln_select)

        # Tags for severity colors
        self.vulns_tree.tag_configure("Critical", foreground="#ff4444")
        self.vulns_tree.tag_configure("High", foreground="#ff8800")
        self.vulns_tree.tag_configure("Medium", foreground="#ffcc00")
        self.vulns_tree.tag_configure("Low", foreground="#00aaff")
        self.vulns_tree.tag_configure("Info", foreground="#00cc00")

    def _build_web_tab(self):
        """Build the website scanner tab."""
        # Top config bar
        web_config = ttk.Frame(self.web_frame, style="Card.TFrame")
        web_config.pack(fill=tk.X, padx=5, pady=(5, 3))

        config_inner = ttk.Frame(web_config, style="Card.TFrame")
        config_inner.pack(fill=tk.X, padx=10, pady=8)

        ttk.Label(config_inner, text="URL:", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.web_url_entry = ttk.Entry(config_inner, width=40, font=("Consolas", 11))
        self.web_url_entry.pack(side=tk.LEFT, padx=(8, 15))
        self.web_url_entry.insert(0, "https://example.com")
        self.web_url_entry.bind("<Return>", lambda e: self._start_web_scan())

        self.web_dir_check_var = tk.BooleanVar(value=True)
        dir_check = tk.Checkbutton(
            config_inner, text="Directory Scan",
            variable=self.web_dir_check_var,
            bg=DarkTheme.BG_SECONDARY, fg=DarkTheme.FG_PRIMARY,
            selectcolor=DarkTheme.BG_INPUT,
            activebackground=DarkTheme.BG_SECONDARY,
            activeforeground=DarkTheme.FG_PRIMARY,
            font=("Segoe UI", 10),
        )
        dir_check.pack(side=tk.LEFT, padx=(0, 15))

        self.web_scan_button = ttk.Button(
            config_inner, text="Scan Website",
            style="Scan.TButton", command=self._start_web_scan,
        )
        self.web_scan_button.pack(side=tk.RIGHT, padx=(5, 0))

        self.web_stop_button = ttk.Button(
            config_inner, text="Stop",
            style="Stop.TButton", command=self._stop_web_scan,
            state="disabled",
        )
        self.web_stop_button.pack(side=tk.RIGHT, padx=(5, 0))

        # Summary bar
        self.web_summary = ttk.Label(
            self.web_frame, text="Enter a URL and click Scan Website.",
            font=("Segoe UI", 10), foreground=DarkTheme.FG_SECONDARY,
        )
        self.web_summary.pack(fill=tk.X, padx=10, pady=(5, 3))

        # Findings treeview
        columns = ("severity", "category", "title", "description")
        self.web_tree = ttk.Treeview(
            self.web_frame, columns=columns, show="headings", height=12,
        )

        self.web_tree.heading("severity", text="Severity")
        self.web_tree.heading("category", text="Category")
        self.web_tree.heading("title", text="Finding")
        self.web_tree.heading("description", text="Details")

        self.web_tree.column("severity", width=80, anchor="center")
        self.web_tree.column("category", width=90, anchor="center")
        self.web_tree.column("title", width=250)
        self.web_tree.column("description", width=350)

        # Tags for severity colors
        self.web_tree.tag_configure("Critical", foreground="#ff4444")
        self.web_tree.tag_configure("High", foreground="#ff8800")
        self.web_tree.tag_configure("Medium", foreground="#ffcc00")
        self.web_tree.tag_configure("Low", foreground="#00aaff")
        self.web_tree.tag_configure("Info", foreground="#00cc00")

        web_scroll = ttk.Scrollbar(self.web_frame, orient=tk.VERTICAL,
                                    command=self.web_tree.yview)
        self.web_tree.configure(yscrollcommand=web_scroll.set)

        self.web_tree.pack(fill=tk.BOTH, expand=True, padx=10, side=tk.LEFT)
        web_scroll.pack(fill=tk.Y, side=tk.RIGHT, padx=(0, 10))

        # Detail panel at bottom
        self.web_detail = scrolledtext.ScrolledText(
            self.web_frame, height=5, wrap=tk.WORD,
            bg=DarkTheme.BG_SECONDARY, fg=DarkTheme.FG_PRIMARY,
            font=("Consolas", 10), insertbackground=DarkTheme.FG_PRIMARY,
            relief="flat", state="disabled",
        )
        self.web_detail.pack(fill=tk.X, padx=10, pady=(3, 5), side=tk.BOTTOM)

        # Bind selection
        self.web_tree.bind("<<TreeviewSelect>>", self._on_web_finding_select)

    def _build_adv_tab(self):
        """Build the advanced scanner tab (SQLi, XSS, CSRF, etc.)."""
        # Top config bar
        adv_config = ttk.Frame(self.adv_frame, style="Card.TFrame")
        adv_config.pack(fill=tk.X, padx=5, pady=(5, 3))

        config_inner = ttk.Frame(adv_config, style="Card.TFrame")
        config_inner.pack(fill=tk.X, padx=10, pady=8)

        ttk.Label(config_inner, text="URL:", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.adv_url_entry = ttk.Entry(config_inner, width=35, font=("Consolas", 11))
        self.adv_url_entry.pack(side=tk.LEFT, padx=(8, 10))
        self.adv_url_entry.insert(0, "https://example.com")
        self.adv_url_entry.bind("<Return>", lambda e: self._start_adv_scan())

        self.adv_scan_button = ttk.Button(
            config_inner, text="Run Advanced Scan",
            style="Scan.TButton", command=self._start_adv_scan,
        )
        self.adv_scan_button.pack(side=tk.RIGHT, padx=(5, 0))

        self.adv_stop_button = ttk.Button(
            config_inner, text="Stop",
            style="Stop.TButton", command=self._stop_adv_scan,
            state="disabled",
        )
        self.adv_stop_button.pack(side=tk.RIGHT, padx=(5, 0))

        # Scan type checkboxes
        checks_frame = ttk.Frame(self.adv_frame, style="Card.TFrame")
        checks_frame.pack(fill=tk.X, padx=5, pady=(0, 3))

        checks_inner = ttk.Frame(checks_frame, style="Card.TFrame")
        checks_inner.pack(fill=tk.X, padx=10, pady=5)

        self.adv_sqli_var = tk.BooleanVar(value=True)
        self.adv_xss_var = tk.BooleanVar(value=True)
        self.adv_csrf_var = tk.BooleanVar(value=True)
        self.adv_redirect_var = tk.BooleanVar(value=True)
        self.adv_cors_var = tk.BooleanVar(value=True)
        self.adv_cookie_var = tk.BooleanVar(value=True)

        check_opts = [
            ("SQL Injection", self.adv_sqli_var),
            ("XSS", self.adv_xss_var),
            ("CSRF", self.adv_csrf_var),
            ("Open Redirect", self.adv_redirect_var),
            ("CORS", self.adv_cors_var),
            ("Cookies", self.adv_cookie_var),
        ]
        for label, var in check_opts:
            cb = tk.Checkbutton(
                checks_inner, text=label, variable=var,
                bg=DarkTheme.BG_SECONDARY, fg=DarkTheme.FG_PRIMARY,
                selectcolor=DarkTheme.BG_INPUT,
                activebackground=DarkTheme.BG_SECONDARY,
                activeforeground=DarkTheme.FG_PRIMARY,
                font=("Segoe UI", 9),
            )
            cb.pack(side=tk.LEFT, padx=(0, 12))

        # Summary bar
        self.adv_summary = ttk.Label(
            self.adv_frame, text="Select scan types and click Run Advanced Scan.",
            font=("Segoe UI", 10), foreground=DarkTheme.FG_SECONDARY,
        )
        self.adv_summary.pack(fill=tk.X, padx=10, pady=(5, 3))

        # Findings treeview
        columns = ("severity", "scanner", "title", "parameter", "description")
        self.adv_tree = ttk.Treeview(
            self.adv_frame, columns=columns, show="headings", height=10,
        )

        self.adv_tree.heading("severity", text="Severity")
        self.adv_tree.heading("scanner", text="Scanner")
        self.adv_tree.heading("title", text="Finding")
        self.adv_tree.heading("parameter", text="Parameter")
        self.adv_tree.heading("description", text="Details")

        self.adv_tree.column("severity", width=70, anchor="center")
        self.adv_tree.column("scanner", width=70, anchor="center")
        self.adv_tree.column("title", width=200)
        self.adv_tree.column("parameter", width=80, anchor="center")
        self.adv_tree.column("description", width=300)

        self.adv_tree.tag_configure("Critical", foreground="#ff4444")
        self.adv_tree.tag_configure("High", foreground="#ff8800")
        self.adv_tree.tag_configure("Medium", foreground="#ffcc00")
        self.adv_tree.tag_configure("Low", foreground="#00aaff")
        self.adv_tree.tag_configure("Info", foreground="#00cc00")

        adv_scroll = ttk.Scrollbar(self.adv_frame, orient=tk.VERTICAL,
                                    command=self.adv_tree.yview)
        self.adv_tree.configure(yscrollcommand=adv_scroll.set)

        self.adv_tree.pack(fill=tk.BOTH, expand=True, padx=10, side=tk.LEFT)
        adv_scroll.pack(fill=tk.Y, side=tk.RIGHT, padx=(0, 10))

        # Detail panel at bottom
        self.adv_detail = scrolledtext.ScrolledText(
            self.adv_frame, height=5, wrap=tk.WORD,
            bg=DarkTheme.BG_SECONDARY, fg=DarkTheme.FG_PRIMARY,
            font=("Consolas", 10), insertbackground=DarkTheme.FG_PRIMARY,
            relief="flat", state="disabled",
        )
        self.adv_detail.pack(fill=tk.X, padx=10, pady=(3, 5), side=tk.BOTTOM)

        # Bind selection
        self.adv_tree.bind("<<TreeviewSelect>>", self._on_adv_finding_select)

    def _build_extra_tab(self):
        """Build the extra scanner tab (Subdomains, DirBrute, API)."""
        # Top config bar
        extra_config = ttk.Frame(self.extra_frame, style="Card.TFrame")
        extra_config.pack(fill=tk.X, padx=5, pady=(5, 3))

        config_inner = ttk.Frame(extra_config, style="Card.TFrame")
        config_inner.pack(fill=tk.X, padx=10, pady=8)

        ttk.Label(config_inner, text="Target:", style="Card.TLabel",
                  font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)
        self.extra_url_entry = ttk.Entry(config_inner, width=35,
                                         font=("Consolas", 11))
        self.extra_url_entry.pack(side=tk.LEFT, padx=(8, 10))
        self.extra_url_entry.insert(0, "example.com")
        self.extra_url_entry.bind("<Return>",
                                  lambda e: self._start_extra_scan())

        self.extra_scan_button = ttk.Button(
            config_inner, text="Run Recon & API Scan",
            style="Scan.TButton", command=self._start_extra_scan,
        )
        self.extra_scan_button.pack(side=tk.RIGHT, padx=(5, 0))

        self.extra_stop_button = ttk.Button(
            config_inner, text="Stop",
            style="Stop.TButton", command=self._stop_extra_scan,
            state="disabled",
        )
        self.extra_stop_button.pack(side=tk.RIGHT, padx=(5, 0))

        # Scan type checkboxes
        checks_frame = ttk.Frame(self.extra_frame, style="Card.TFrame")
        checks_frame.pack(fill=tk.X, padx=5, pady=(0, 3))

        checks_inner = ttk.Frame(checks_frame, style="Card.TFrame")
        checks_inner.pack(fill=tk.X, padx=10, pady=5)

        self.extra_subdomain_var = tk.BooleanVar(value=True)
        self.extra_dirbrute_var = tk.BooleanVar(value=True)
        self.extra_api_var = tk.BooleanVar(value=True)

        check_opts = [
            ("Subdomain Enumeration", self.extra_subdomain_var),
            ("Directory Brute Force", self.extra_dirbrute_var),
            ("API Security", self.extra_api_var),
        ]
        for label, var in check_opts:
            cb = tk.Checkbutton(
                checks_inner, text=label, variable=var,
                bg=DarkTheme.BG_SECONDARY, fg=DarkTheme.FG_PRIMARY,
                selectcolor=DarkTheme.BG_INPUT,
                activebackground=DarkTheme.BG_SECONDARY,
                activeforeground=DarkTheme.FG_PRIMARY,
                font=("Segoe UI", 9),
            )
            cb.pack(side=tk.LEFT, padx=(0, 12))

        # Summary bar
        self.extra_summary = ttk.Label(
            self.extra_frame,
            text="Select scan types and click Run Recon & API Scan.",
            font=("Segoe UI", 10), foreground=DarkTheme.FG_SECONDARY,
        )
        self.extra_summary.pack(fill=tk.X, padx=10, pady=(5, 3))

        # Findings treeview
        columns = ("severity", "scanner", "title", "description")
        self.extra_tree = ttk.Treeview(
            self.extra_frame, columns=columns, show="headings", height=10,
        )

        self.extra_tree.heading("severity", text="Severity")
        self.extra_tree.heading("scanner", text="Scanner")
        self.extra_tree.heading("title", text="Finding")
        self.extra_tree.heading("description", text="Details")

        self.extra_tree.column("severity", width=70, anchor="center")
        self.extra_tree.column("scanner", width=90, anchor="center")
        self.extra_tree.column("title", width=250)
        self.extra_tree.column("description", width=400)

        self.extra_tree.tag_configure("Critical", foreground="#ff4444")
        self.extra_tree.tag_configure("High", foreground="#ff8800")
        self.extra_tree.tag_configure("Medium", foreground="#ffcc00")
        self.extra_tree.tag_configure("Low", foreground="#00aaff")
        self.extra_tree.tag_configure("Info", foreground="#00cc00")

        extra_scroll = ttk.Scrollbar(self.extra_frame, orient=tk.VERTICAL,
                                      command=self.extra_tree.yview)
        self.extra_tree.configure(yscrollcommand=extra_scroll.set)

        self.extra_tree.pack(fill=tk.BOTH, expand=True, padx=10,
                             side=tk.LEFT)
        extra_scroll.pack(fill=tk.Y, side=tk.RIGHT, padx=(0, 10))

        # Detail panel at bottom
        self.extra_detail = scrolledtext.ScrolledText(
            self.extra_frame, height=5, wrap=tk.WORD,
            bg=DarkTheme.BG_SECONDARY, fg=DarkTheme.FG_PRIMARY,
            font=("Consolas", 10), insertbackground=DarkTheme.FG_PRIMARY,
            relief="flat", state="disabled",
        )
        self.extra_detail.pack(fill=tk.X, padx=10, pady=(3, 5),
                               side=tk.BOTTOM)

        # Bind selection
        self.extra_tree.bind("<<TreeviewSelect>>",
                             self._on_extra_finding_select)

    def _build_console_tab(self):
        """Build the console/log tab."""
        self.console_text = scrolledtext.ScrolledText(
            self.console_frame, wrap=tk.WORD,
            bg=DarkTheme.BG_PRIMARY, fg=DarkTheme.FG_PRIMARY,
            font=("Consolas", 10), insertbackground=DarkTheme.FG_PRIMARY,
            relief="flat",
        )
        self.console_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Console text tags
        self.console_text.tag_configure("info", foreground=DarkTheme.FG_ACCENT)
        self.console_text.tag_configure("success", foreground=DarkTheme.FG_SUCCESS)
        self.console_text.tag_configure("warning", foreground=DarkTheme.FG_WARNING)
        self.console_text.tag_configure("error", foreground=DarkTheme.FG_ERROR)
        self.console_text.tag_configure("header",
                                         foreground=DarkTheme.FG_ACCENT,
                                         font=("Consolas", 10, "bold"))

    def _build_export_tab(self):
        """Build the export options tab."""
        export_inner = ttk.Frame(self.export_frame)
        export_inner.pack(expand=True)

        ttk.Label(export_inner, text="Export Scan Results",
                  font=("Segoe UI", 16, "bold"),
                  foreground=DarkTheme.FG_ACCENT).pack(pady=(30, 20))

        ttk.Label(export_inner, text="Choose an export format:",
                  foreground=DarkTheme.FG_SECONDARY).pack(pady=(0, 20))

        btn_frame = ttk.Frame(export_inner)
        btn_frame.pack()

        ttk.Button(btn_frame, text="Export as CSV",
                   style="Export.TButton",
                   command=lambda: self._export("csv")).pack(side=tk.LEFT, padx=10)

        ttk.Button(btn_frame, text="Export as HTML Report",
                   style="Export.TButton",
                   command=lambda: self._export("html")).pack(side=tk.LEFT, padx=10)

        ttk.Button(btn_frame, text="Copy as Text",
                   style="Export.TButton",
                   command=self._copy_text_report).pack(side=tk.LEFT, padx=10)

    def _build_status_bar(self):
        """Build the status bar at the bottom."""
        status_frame = ttk.Frame(self, style="Card.TFrame")
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))

        inner = tk.Frame(status_frame, bg=DarkTheme.BG_TERTIARY)
        inner.pack(fill=tk.X, padx=1, pady=1)

        self.status_label = tk.Label(
            inner, text="Ready", bg=DarkTheme.BG_TERTIARY,
            fg=DarkTheme.FG_SECONDARY, font=("Segoe UI", 9),
            anchor="w",
        )
        self.status_label.pack(side=tk.LEFT, padx=10, pady=4)

        self.progress_label = tk.Label(
            inner, text="", bg=DarkTheme.BG_TERTIARY,
            fg=DarkTheme.FG_ACCENT, font=("Segoe UI", 9),
        )
        self.progress_label.pack(side=tk.RIGHT, padx=10, pady=4)

        self.progress_bar = ttk.Progressbar(
            inner, mode="determinate", length=200,
            style="Scan.Horizontal.TProgressbar",
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=(0, 10), pady=4)

    # ── Event Handlers ──────────────────────────────────────────────

    def _on_scan_type_change(self, event=None):
        """Handle scan type combo change."""
        scan_type = self.scan_type_var.get()
        if scan_type == "Custom Ports":
            self.ports_entry.configure(state="normal")
        else:
            self.ports_entry.configure(state="disabled")

    def _on_vuln_select(self, event=None):
        """Show vulnerability details when selected."""
        selection = self.vulns_tree.selection()
        if not selection:
            return

        item = self.vulns_tree.item(selection[0])
        values = item["values"]
        if not values:
            return

        # Find the matching vulnerability
        for vuln in self.current_vulns:
            if vuln.title == values[3]:
                self.vuln_detail.configure(state="normal")
                self.vuln_detail.delete("1.0", tk.END)
                detail = (
                    f"Title: {vuln.title}\n"
                    f"Severity: {vuln.severity}\n"
                    f"Port: {vuln.port} ({vuln.service})\n"
                    f"CVE: {vuln.cve or 'N/A'}\n\n"
                    f"Description:\n{vuln.description}\n\n"
                    f"Recommendation:\n{vuln.recommendation}"
                )
                self.vuln_detail.insert("1.0", detail)
                self.vuln_detail.configure(state="disabled")
                break

    def _on_web_finding_select(self, event=None):
        """Show web finding details when selected."""
        selection = self.web_tree.selection()
        if not selection or not self.current_web_result:
            return

        item = self.web_tree.item(selection[0])
        values = item["values"]
        if not values:
            return

        # Find the matching finding
        for finding in self.current_web_result.findings:
            if finding.title == values[2]:
                self.web_detail.configure(state="normal")
                self.web_detail.delete("1.0", tk.END)
                detail = (
                    f"Title: {finding.title}\n"
                    f"Severity: {finding.severity}\n"
                    f"Category: {finding.category.upper()}\n"
                    f"\nDescription:\n{finding.description}\n"
                )
                if finding.recommendation:
                    detail += f"\nRecommendation:\n{finding.recommendation}"
                if finding.detail:
                    detail += f"\n\nDetail: {finding.detail}"
                self.web_detail.insert("1.0", detail)
                self.web_detail.configure(state="disabled")
                break

    # ── Scanning ─────────────────────────────────────────────────────

    def _start_scan(self):
        """Start the vulnerability scan."""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target IP or hostname.")
            return

        if self.is_scanning:
            return

        # Parse settings
        try:
            timeout = float(self.timeout_var.get())
        except ValueError:
            timeout = 1.5

        try:
            max_threads = int(self.threads_var.get())
        except ValueError:
            max_threads = 100

        # Determine port list
        scan_type_map = {
            "Common Ports": "common",
            "Full Scan (1-65535)": "full",
            "Custom Ports": "custom",
        }
        scan_type = scan_type_map.get(self.scan_type_var.get(), "common")

        custom_ports = None
        if scan_type == "custom":
            try:
                port_str = self.ports_entry.get().strip()
                custom_ports = self._parse_ports(port_str)
                if not custom_ports:
                    raise ValueError("Empty port list")
            except ValueError as e:
                messagebox.showwarning("Warning", f"Invalid port specification: {e}")
                return

        # Update UI state
        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        self.web_scan_button.configure(state="disabled")
        self.adv_scan_button.configure(state="disabled")
        self.extra_scan_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        self.progress_bar["value"] = 0

        # Clear previous results
        self._clear_results()

        # Configure scanner
        self.scanner = PortScanner(
            timeout=timeout,
            max_threads=max_threads,
            on_port_scanned=self._on_port_found,
            on_progress=self._on_scan_progress,
        )

        # Log start
        self._log(f"{'=' * 55}", "header")
        self._log("  ANDY VULNSCANNER - Starting Scan", "header")
        self._log(f"{'=' * 55}", "header")
        self._log(f"Target: {target}", "info")
        self._log(f"Scan Type: {self.scan_type_var.get()}", "info")
        self._log(f"Timeout: {timeout}s | Threads: {max_threads}", "info")
        self._log("")
        self.status_label.configure(text=f"Scanning {target}...")

        # Run scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(target, scan_type, custom_ports),
            daemon=True,
        )
        self.scan_thread.start()

    def _run_scan(self, target: str, scan_type: str, custom_ports: Optional[list[int]]):
        """Run the scan in a background thread."""
        start_time = time.time()

        try:
            # Resolve target
            self._log(f"Resolving {target}...", "info")
            result = self.scanner.scan(
                target=target,
                scan_type=scan_type,
                ports=custom_ports,
            )
            result.scan_time = time.time() - start_time

            self.current_result = result

            # Log results
            self._log("")
            self._log(f"Scan completed in {result.scan_time:.2f}s", "success")
            self._log(f"IP: {result.ip_address} | Host: {result.hostname or 'N/A'}",
                      "info")
            self._log(f"Open ports found: {len(result.ports)}", "success")

            # Update ports summary
            self.after(0, lambda: self.ports_summary.configure(
                text=f"Target: {result.ip_address} ({result.hostname or 'N/A'})  |  "
                     f"Open Ports: {len(result.ports)}  |  "
                     f"Scan Time: {result.scan_time:.2f}s",
                foreground=DarkTheme.FG_SUCCESS,
            ))

            # Check vulnerabilities
            self._log("")
            self._log("Checking for known vulnerabilities...", "info")
            vulns = self.vuln_checker.check_vulnerabilities(result)
            self.current_vulns = vulns

            # Display vulnerabilities
            self.after(0, lambda: self._display_vulns(vulns))

            if vulns:
                self._log(f"Found {len(vulns)} potential vulnerability(ies)!", "warning")
                for v in vulns:
                    self._log(f"  [{v.severity}] {v.title} (Port {v.port})", "error")
            else:
                self._log("No known vulnerabilities detected.", "success")

            # Risk score
            score, label = self.vuln_checker.get_risk_score(vulns)
            self._log(f"\nRisk Score: {score}/100 - {label}", "warning" if score > 0 else "success")

        except ValueError as exc:
            self._log(f"Error: {exc}", "error")
            msg = str(exc)
            self.after(0, lambda: messagebox.showerror("Scan Error", msg))
        except Exception as exc:
            self._log(f"Unexpected error: {exc}", "error")
            msg = str(exc)
            self.after(0, lambda: messagebox.showerror("Error", msg))
        finally:
            self.after(0, self._scan_finished)

    def _scan_finished(self):
        """Called when scan is complete (on main thread)."""
        self.is_scanning = False
        self.scan_button.configure(state="normal")
        self.web_scan_button.configure(state="normal")
        self.adv_scan_button.configure(state="normal")
        self.extra_scan_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        self.progress_bar["value"] = 100
        self.status_label.configure(text="Scan complete")

    def _stop_scan(self):
        """Stop the running scan."""
        if self.is_scanning:
            self.scanner.stop()
            self._log("\nScan stopped by user.", "warning")
            self.status_label.configure(text="Scan stopped")

    def _on_adv_finding_select(self, event=None):
        """Show advanced finding details when selected."""
        selection = self.adv_tree.selection()
        if not selection or not self.current_adv_result:
            return

        item = self.adv_tree.item(selection[0])
        values = item["values"]
        if not values:
            return

        for finding in self.current_adv_result.findings:
            if finding.title == values[2]:
                self.adv_detail.configure(state="normal")
                self.adv_detail.delete("1.0", tk.END)
                detail = (
                    f"Title: {finding.title}\n"
                    f"Severity: {finding.severity}\n"
                    f"Scanner: {finding.scanner.upper()}\n"
                )
                if finding.parameter:
                    detail += f"Parameter: {finding.parameter}\n"
                detail += f"\nDescription:\n{finding.description}\n"
                if finding.payload:
                    detail += f"\nPayload: {finding.payload}"
                if finding.evidence:
                    detail += f"\nEvidence: {finding.evidence}"
                if finding.recommendation:
                    detail += f"\n\nRecommendation:\n{finding.recommendation}"
                self.adv_detail.insert("1.0", detail)
                self.adv_detail.configure(state="disabled")
                break

    # ── Web Scanning ─────────────────────────────────────────────────

    def _start_web_scan(self):
        """Start a website vulnerability scan."""
        url = self.web_url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL to scan.")
            return

        if self.is_scanning:
            return

        self.is_scanning = True
        self.web_scan_button.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.adv_scan_button.configure(state="disabled")
        self.extra_scan_button.configure(state="disabled")
        self.web_stop_button.configure(state="normal")
        self.progress_bar["value"] = 0

        # Clear previous web results
        for item in self.web_tree.get_children():
            self.web_tree.delete(item)
        self.web_summary.configure(
            text="Scanning...", foreground=DarkTheme.FG_SECONDARY,
        )
        self.web_detail.configure(state="normal")
        self.web_detail.delete("1.0", tk.END)
        self.web_detail.configure(state="disabled")
        self.current_web_result = None

        # Clear console
        self.console_text.delete("1.0", tk.END)

        # Log start
        self._log(f"{'=' * 55}", "header")
        self._log("  ANDY VULNSCANNER - Website Scan", "header")
        self._log(f"{'=' * 55}", "header")
        self._log(f"URL: {url}", "info")
        self._log(f"Directory Scan: {'Yes' if self.web_dir_check_var.get() else 'No'}", "info")
        self._log("")
        self.status_label.configure(text=f"Scanning {url}...")

        # Configure web scanner
        self.web_scanner = WebScanner(
            on_finding=self._on_web_finding,
            on_progress=self._on_scan_progress,
            on_log=self._log,
        )

        # Run scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_web_scan,
            args=(url, self.web_dir_check_var.get()),
            daemon=True,
        )
        self.scan_thread.start()

    def _run_web_scan(self, url: str, check_dirs: bool):
        """Run the website scan in a background thread."""
        start_time = time.time()

        try:
            result = self.web_scanner.scan(url, check_dirs=check_dirs)
            result.scan_time = time.time() - start_time
            self.current_web_result = result

            # Log summary
            self._log("")
            self._log(f"Website scan completed in {result.scan_time:.2f}s", "success")
            self._log(f"Status: {result.status_code} | Server: {result.server}", "info")
            self._log(f"Findings: {len(result.findings)}", "warning" if result.findings else "success")
            if result.technologies:
                self._log(f"Technologies: {', '.join(result.technologies)}", "info")
            if result.directories_found:
                self._log(f"Directories found: {len(result.directories_found)}", "info")

            # Display findings in treeview
            self.after(0, lambda: self._display_web_findings(result))

        except Exception as exc:
            self._log(f"Error: {exc}", "error")
            msg = str(exc)
            self.after(0, lambda: messagebox.showerror("Web Scan Error", msg))
        finally:
            self.after(0, self._web_scan_finished)

    def _web_scan_finished(self):
        """Called when web scan is complete (on main thread)."""
        self.is_scanning = False
        self.web_scan_button.configure(state="normal")
        self.scan_button.configure(state="normal")
        self.adv_scan_button.configure(state="normal")
        self.extra_scan_button.configure(state="normal")
        self.web_stop_button.configure(state="disabled")
        self.progress_bar["value"] = 100
        self.status_label.configure(text="Web scan complete")

    def _stop_web_scan(self):
        """Stop the running web scan."""
        if self.is_scanning:
            self.web_scanner.stop()
            self._log("\nWeb scan stopped by user.", "warning")
            self.status_label.configure(text="Web scan stopped")

    # ── Advanced Scanning ─────────────────────────────────────────────

    def _start_adv_scan(self):
        """Start an advanced vulnerability scan."""
        url = self.adv_url_entry.get().strip()
        if not url:
            messagebox.showwarning("Warning", "Please enter a URL to scan.")
            return

        if self.is_scanning:
            return

        self.is_scanning = True
        self.adv_scan_button.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.web_scan_button.configure(state="disabled")
        self.extra_scan_button.configure(state="disabled")
        self.adv_stop_button.configure(state="normal")
        self.progress_bar["value"] = 0

        # Clear previous results
        for item in self.adv_tree.get_children():
            self.adv_tree.delete(item)
        self.adv_summary.configure(
            text="Scanning...", foreground=DarkTheme.FG_SECONDARY,
        )
        self.adv_detail.configure(state="normal")
        self.adv_detail.delete("1.0", tk.END)
        self.adv_detail.configure(state="disabled")
        self.current_adv_result = None

        # Clear console
        self.console_text.delete("1.0", tk.END)

        # Log start
        self._log(f"{'=' * 55}", "header")
        self._log("  ANDY VULNSCANNER - Advanced Scan", "header")
        self._log(f"{'=' * 55}", "header")
        self._log(f"URL: {url}", "info")

        scanners = []
        if self.adv_sqli_var.get():
            scanners.append("SQLi")
        if self.adv_xss_var.get():
            scanners.append("XSS")
        if self.adv_csrf_var.get():
            scanners.append("CSRF")
        if self.adv_redirect_var.get():
            scanners.append("Redirect")
        if self.adv_cors_var.get():
            scanners.append("CORS")
        if self.adv_cookie_var.get():
            scanners.append("Cookies")
        self._log(f"Scanners: {', '.join(scanners)}", "info")
        self._log("")
        self.status_label.configure(text=f"Advanced scanning {url}...")

        # Configure scanner
        self.adv_scanner = AdvancedScanner(
            on_finding=self._on_adv_finding,
            on_progress=self._on_scan_progress,
            on_log=self._log,
        )

        # Run scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_adv_scan,
            args=(
                url,
                self.adv_sqli_var.get(),
                self.adv_xss_var.get(),
                self.adv_csrf_var.get(),
                self.adv_redirect_var.get(),
                self.adv_cors_var.get(),
                self.adv_cookie_var.get(),
            ),
            daemon=True,
        )
        self.scan_thread.start()

    def _run_adv_scan(
        self, url: str, sqli: bool, xss: bool, csrf: bool,
        redirect: bool, cors: bool, cookies: bool,
    ):
        """Run the advanced scan in a background thread."""
        start_time = time.time()

        try:
            result = self.adv_scanner.scan(
                url, sqli=sqli, xss=xss, csrf=csrf,
                open_redirect=redirect, cors=cors, cookies=cookies,
            )
            result.scan_time = time.time() - start_time
            self.current_adv_result = result

            self._log("")
            self._log(f"Advanced scan completed in {result.scan_time:.2f}s", "success")
            self._log(f"Findings: {len(result.findings)}", "warning" if result.findings else "success")
            self._log(f"Parameters tested: {result.parameters_tested}", "info")
            if result.forms_found:
                self._log(f"Forms found: {result.forms_found}", "info")

            self.after(0, lambda: self._display_adv_findings(result))

        except Exception as exc:
            self._log(f"Error: {exc}", "error")
            msg = str(exc)
            self.after(0, lambda: messagebox.showerror("Advanced Scan Error", msg))
        finally:
            self.after(0, self._adv_scan_finished)

    def _adv_scan_finished(self):
        """Called when advanced scan is complete (on main thread)."""
        self.is_scanning = False
        self.adv_scan_button.configure(state="normal")
        self.scan_button.configure(state="normal")
        self.web_scan_button.configure(state="normal")
        self.extra_scan_button.configure(state="normal")
        self.adv_stop_button.configure(state="disabled")
        self.progress_bar["value"] = 100
        self.status_label.configure(text="Advanced scan complete")

    def _stop_adv_scan(self):
        """Stop the running advanced scan."""
        if self.is_scanning:
            self.adv_scanner.stop()
            self._log("\nAdvanced scan stopped by user.", "warning")
            self.status_label.configure(text="Advanced scan stopped")

    # ── Extra Scanning (Subdomains, DirBrute, API) ────────────────

    def _start_extra_scan(self):
        """Start an extra recon & API scan."""
        target = self.extra_url_entry.get().strip()
        if not target:
            messagebox.showwarning("Warning", "Please enter a target.")
            return

        if self.is_scanning:
            return

        self.is_scanning = True
        self.extra_scan_button.configure(state="disabled")
        self.scan_button.configure(state="disabled")
        self.web_scan_button.configure(state="disabled")
        self.adv_scan_button.configure(state="disabled")
        self.extra_stop_button.configure(state="normal")
        self.progress_bar["value"] = 0

        # Clear previous results
        for item in self.extra_tree.get_children():
            self.extra_tree.delete(item)
        self.extra_summary.configure(
            text="Scanning...", foreground=DarkTheme.FG_SECONDARY,
        )
        self.extra_detail.configure(state="normal")
        self.extra_detail.delete("1.0", tk.END)
        self.extra_detail.configure(state="disabled")
        self.current_extra_result = None

        # Clear console
        self.console_text.delete("1.0", tk.END)

        # Log start
        self._log(f"{'=' * 55}", "header")
        self._log("  ANDY VULNSCANNER - Recon & API Scan", "header")
        self._log(f"{'=' * 55}", "header")
        self._log(f"Target: {target}", "info")

        scanners = []
        if self.extra_subdomain_var.get():
            scanners.append("Subdomains")
        if self.extra_dirbrute_var.get():
            scanners.append("DirBrute")
        if self.extra_api_var.get():
            scanners.append("API")
        self._log(f"Scanners: {', '.join(scanners)}", "info")
        self._log("")
        self.status_label.configure(text=f"Recon scanning {target}...")

        # Configure scanner
        self.extra_scanner = ExtraScanner(
            on_finding=self._on_extra_finding,
            on_progress=self._on_scan_progress,
            on_log=self._log,
        )

        # Run scan in background thread
        self.scan_thread = threading.Thread(
            target=self._run_extra_scan,
            args=(
                target,
                self.extra_subdomain_var.get(),
                self.extra_dirbrute_var.get(),
                self.extra_api_var.get(),
            ),
            daemon=True,
        )
        self.scan_thread.start()

    def _run_extra_scan(
        self, target: str, subdomains: bool, dirbrute: bool,
        api_scan: bool,
    ):
        """Run the extra scan in a background thread."""
        start_time = time.time()

        try:
            result = self.extra_scanner.scan(
                target, subdomains=subdomains, dirbrute=dirbrute,
                api_scan=api_scan,
            )
            result.scan_time = time.time() - start_time
            self.current_extra_result = result

            self._log("")
            self._log(
                f"Recon & API scan completed in {result.scan_time:.2f}s",
                "success",
            )
            self._log(
                f"Findings: {len(result.findings)}",
                "warning" if result.findings else "success",
            )
            if result.subdomains_found:
                self._log(
                    f"Subdomains found: {result.subdomains_found}", "info",
                )
            if result.directories_found:
                self._log(
                    f"Directories found: {result.directories_found}", "info",
                )
            if result.api_issues_found:
                self._log(
                    f"API issues found: {result.api_issues_found}", "info",
                )

            self.after(0, lambda: self._display_extra_findings(result))

        except Exception as exc:
            self._log(f"Error: {exc}", "error")
            msg = str(exc)
            self.after(
                0, lambda: messagebox.showerror("Recon Scan Error", msg),
            )
        finally:
            self.after(0, self._extra_scan_finished)

    def _extra_scan_finished(self):
        """Called when extra scan is complete (on main thread)."""
        self.is_scanning = False
        self.extra_scan_button.configure(state="normal")
        self.scan_button.configure(state="normal")
        self.web_scan_button.configure(state="normal")
        self.adv_scan_button.configure(state="normal")
        self.extra_stop_button.configure(state="disabled")
        self.progress_bar["value"] = 100
        self.status_label.configure(text="Recon & API scan complete")

    def _stop_extra_scan(self):
        """Stop the running extra scan."""
        if self.is_scanning:
            self.extra_scanner.stop()
            self._log("\nRecon & API scan stopped by user.", "warning")
            self.status_label.configure(text="Recon scan stopped")

    def _on_extra_finding(self, finding: ExtraFinding):
        """Callback when an extra finding is discovered."""
        self.after(0, lambda f=finding: self.extra_tree.insert(
            "", tk.END,
            values=(f.severity, f.scanner.upper(), f.title,
                    f.description[:100]),
            tags=(f.severity,),
        ))

    def _on_extra_finding_select(self, event):
        """Show details when an extra finding is selected."""
        selection = self.extra_tree.selection()
        if not selection or not self.current_extra_result:
            return

        item = selection[0]
        values = self.extra_tree.item(item, "values")
        if not values:
            return

        # Find the matching finding
        for finding in self.current_extra_result.findings:
            if finding.title == values[2]:
                self.extra_detail.configure(state="normal")
                self.extra_detail.delete("1.0", tk.END)
                detail = (
                    f"Title: {finding.title}\n"
                    f"Severity: {finding.severity}\n"
                    f"Scanner: {finding.scanner}\n\n"
                    f"Description:\n{finding.description}\n\n"
                    f"Evidence: {finding.evidence}\n\n"
                    f"Recommendation:\n{finding.recommendation}"
                )
                self.extra_detail.insert("1.0", detail)
                self.extra_detail.configure(state="disabled")
                break

    def _display_extra_findings(self, result: ExtraScanResult):
        """Display all extra scan findings."""
        for item in self.extra_tree.get_children():
            self.extra_tree.delete(item)

        for finding in result.findings:
            self.extra_tree.insert(
                "", tk.END,
                values=(finding.severity, finding.scanner.upper(),
                        finding.title, finding.description[:100]),
                tags=(finding.severity,),
            )

        severity_counts: dict[str, int] = {}
        for f in result.findings:
            severity_counts[f.severity] = (
                severity_counts.get(f.severity, 0) + 1
            )

        counts_str = ", ".join(
            f"{count} {sev}" for sev, count in severity_counts.items()
        )

        info_parts = [f"Target: {result.target}"]
        info_parts.append(f"Findings: {len(result.findings)}")
        if counts_str:
            info_parts.append(f"({counts_str})")
        info_parts.append(f"Time: {result.scan_time:.2f}s")

        self.extra_summary.configure(
            text="  |  ".join(info_parts),
            foreground=(
                DarkTheme.FG_WARNING if result.findings
                else DarkTheme.FG_SUCCESS
            ),
        )

    def _on_adv_finding(self, finding: AdvFinding):
        """Callback when an advanced finding is discovered."""
        self.after(0, lambda f=finding: self.adv_tree.insert(
            "", tk.END,
            values=(f.severity, f.scanner.upper(), f.title,
                    f.parameter or "-", f.description[:100]),
            tags=(f.severity,),
        ))

    def _display_adv_findings(self, result: AdvScanResult):
        """Display all advanced scan findings."""
        for item in self.adv_tree.get_children():
            self.adv_tree.delete(item)

        for finding in result.findings:
            self.adv_tree.insert(
                "", tk.END,
                values=(finding.severity, finding.scanner.upper(),
                        finding.title, finding.parameter or "-",
                        finding.description[:100]),
                tags=(finding.severity,),
            )

        severity_counts = {}
        for f in result.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        counts_str = ", ".join(
            f"{count} {sev}" for sev, count in severity_counts.items()
        )

        info_parts = [f"URL: {result.url}"]
        info_parts.append(f"Findings: {len(result.findings)}")
        if counts_str:
            info_parts.append(f"({counts_str})")
        info_parts.append(f"Time: {result.scan_time:.2f}s")

        self.adv_summary.configure(
            text="  |  ".join(info_parts),
            foreground=DarkTheme.FG_WARNING if result.findings else DarkTheme.FG_SUCCESS,
        )

    def _on_web_finding(self, finding: WebFinding):
        """Callback when a web finding is discovered (from scanner thread)."""
        self.after(0, lambda f=finding: self.web_tree.insert(
            "", tk.END,
            values=(f.severity, f.category.upper(), f.title,
                    f.description[:100]),
            tags=(f.severity,),
        ))

    def _display_web_findings(self, result: WebScanResult):
        """Display all web scan findings in the treeview."""
        # Clear and re-populate (some findings may have been added in real-time)
        for item in self.web_tree.get_children():
            self.web_tree.delete(item)

        for finding in result.findings:
            self.web_tree.insert(
                "", tk.END,
                values=(finding.severity, finding.category.upper(),
                        finding.title, finding.description[:100]),
                tags=(finding.severity,),
            )

        # Update summary
        severity_counts = {}
        for f in result.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        counts_str = ", ".join(
            f"{count} {sev}" for sev, count in severity_counts.items()
        )

        info_parts = [f"URL: {result.url}"]
        if result.ip_address:
            info_parts.append(f"IP: {result.ip_address}")
        info_parts.append(f"Findings: {len(result.findings)}")
        if counts_str:
            info_parts.append(f"({counts_str})")
        info_parts.append(f"Time: {result.scan_time:.2f}s")

        self.web_summary.configure(
            text="  |  ".join(info_parts),
            foreground=DarkTheme.FG_WARNING if result.findings else DarkTheme.FG_SUCCESS,
        )

    def _on_port_found(self, port_result: PortResult):
        """Callback when an open port is found (from scanner thread)."""
        self._log(
            f"  OPEN  {port_result.port}/tcp  {port_result.service:<15}  "
            f"{port_result.version or port_result.banner[:50] or ''}",
            "success",
        )
        # Add to treeview (thread-safe)
        self.after(0, lambda pr=port_result: self.ports_tree.insert(
            "", tk.END,
            values=(
                pr.port,
                pr.state.upper(),
                pr.service,
                pr.version or pr.banner[:80] or "",
            ),
        ))

    def _on_scan_progress(self, scanned: int, total: int):
        """Callback for scan progress (from scanner thread)."""
        pct = (scanned / total) * 100 if total > 0 else 0
        self.after(0, lambda: self._update_progress(pct, scanned, total))

    def _update_progress(self, pct: float, scanned: int, total: int):
        """Update progress bar and label (on main thread)."""
        self.progress_bar["value"] = pct
        self.progress_label.configure(text=f"{scanned}/{total} ({pct:.0f}%)")

    # ── Display ──────────────────────────────────────────────────────

    def _display_vulns(self, vulns: list[Vulnerability]):
        """Populate the vulnerabilities treeview."""
        for vuln in vulns:
            self.vulns_tree.insert(
                "", tk.END,
                values=(vuln.severity, vuln.port, vuln.service,
                        vuln.title, vuln.cve or "N/A"),
                tags=(vuln.severity,),
            )

        # Update summary
        score, label = self.vuln_checker.get_risk_score(vulns)
        self.vulns_summary.configure(
            text=f"Found {len(vulns)} vulnerability(ies)",
            foreground=DarkTheme.FG_WARNING if vulns else DarkTheme.FG_SUCCESS,
        )

        if score >= 60:
            color = DarkTheme.FG_ERROR
        elif score >= 30:
            color = DarkTheme.FG_WARNING
        elif score > 0:
            color = DarkTheme.FG_ACCENT
        else:
            color = DarkTheme.FG_SUCCESS

        self.risk_label.configure(
            text=f"Risk: {score}/100 ({label})",
            foreground=color,
        )

    def _clear_results(self):
        """Clear all result displays."""
        # Clear ports tree
        for item in self.ports_tree.get_children():
            self.ports_tree.delete(item)
        self.ports_summary.configure(
            text="Scanning...", foreground=DarkTheme.FG_SECONDARY,
        )

        # Clear vulns tree
        for item in self.vulns_tree.get_children():
            self.vulns_tree.delete(item)
        self.vulns_summary.configure(
            text="Checking after scan...", foreground=DarkTheme.FG_SECONDARY,
        )
        self.risk_label.configure(text="")
        self.vuln_detail.configure(state="normal")
        self.vuln_detail.delete("1.0", tk.END)
        self.vuln_detail.configure(state="disabled")

        # Clear console
        self.console_text.delete("1.0", tk.END)

        self.current_result = None
        self.current_vulns = []

    # ── Logging ──────────────────────────────────────────────────────

    def _log(self, message: str, tag: str = ""):
        """Append a message to the console (thread-safe)."""
        def _append():
            self.console_text.insert(tk.END, message + "\n", tag)
            self.console_text.see(tk.END)
        self.after(0, _append)

    # ── Export ────────────────────────────────────────────────────────

    def _export(self, fmt: str):
        """Export results to file."""
        if not self.current_result:
            messagebox.showinfo("Info", "No scan results to export. Run a scan first.")
            return

        if fmt == "csv":
            filepath = filedialog.asksaveasfilename(
                defaultextension=".csv",
                filetypes=[("CSV files", "*.csv")],
                title="Save CSV Report",
                initialfile=f"andy_vulnscan_{self.current_result.target}.csv",
            )
            if filepath:
                ReportExporter.to_csv(self.current_result, self.current_vulns, filepath)
                messagebox.showinfo("Success", f"CSV report saved to:\n{filepath}")
                self._log(f"Report exported: {filepath}", "success")

        elif fmt == "html":
            filepath = filedialog.asksaveasfilename(
                defaultextension=".html",
                filetypes=[("HTML files", "*.html")],
                title="Save HTML Report",
                initialfile=f"andy_vulnscan_{self.current_result.target}.html",
            )
            if filepath:
                ReportExporter.to_html(self.current_result, self.current_vulns, filepath)
                messagebox.showinfo("Success", f"HTML report saved to:\n{filepath}")
                self._log(f"Report exported: {filepath}", "success")

    def _copy_text_report(self):
        """Copy text report to clipboard."""
        if not self.current_result:
            messagebox.showinfo("Info", "No scan results to copy. Run a scan first.")
            return

        text = ReportExporter.to_text(self.current_result, self.current_vulns)
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", "Text report copied to clipboard!")
        self._log("Report copied to clipboard.", "success")

    # ── Utilities ────────────────────────────────────────────────────

    def _parse_ports(self, port_str: str) -> list[int]:
        """Parse a port specification string like '80,443,1000-2000'."""
        ports = []
        for part in port_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                start_port = int(start.strip())
                end_port = int(end.strip())
                if start_port < 1 or end_port > 65535 or start_port > end_port:
                    raise ValueError(f"Invalid range: {part}")
                ports.extend(range(start_port, end_port + 1))
            else:
                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {port}")
                ports.append(port)
        return sorted(set(ports))

    def _on_close(self):
        """Handle window close."""
        if self.is_scanning:
            if messagebox.askyesno("Confirm", "A scan is in progress. Stop and exit?"):
                self.scanner.stop()
                self.web_scanner.stop()
                self.adv_scanner.stop()
                self.extra_scanner.stop()
                self.destroy()
        else:
            self.destroy()
