#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
from pathlib import Path
import platform
import webbrowser
from typing import Optional, List, Dict, Any

# Import our new modular components
from moddoctor.core.scan import scan_mods_directory
from moddoctor.core.analyzer import analyze_mods
from moddoctor.core.fixes import (
    disable_mod_file, open_in_explorer, disable_duplicates, 
    disable_conflicts, disable_all_errors
)
from moddoctor.core.hardware import recommend_jvm_args
from moddoctor.core.report import generate_markdown_report, export_report_to_file
from moddoctor.core.model import ModInfo, Issue, AnalysisResult, Severity
from moddoctor.integrations.modrinth import enrich_mod_info
from moddoctor.settings import load_settings, save_settings, add_recent_mods_dir
from moddoctor.util.cache import clear_cache, get_cache_stats
from moddoctor.util.image_utils import create_placeholder_icon

try:
    from PIL import Image, ImageTk
except ImportError:
    Image = ImageTk = None


class ModpackDoctorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Modpack Doctor - Advanced Mod Analysis")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Load settings
        self.settings = load_settings()
        
        # Analysis data
        self.mods: List[ModInfo] = []
        self.analysis_result: Optional[AnalysisResult] = None
        self.filtered_mods: List[ModInfo] = []
        self.filtered_issues: List[Issue] = []
        
        # GUI state
        self.analysis_running = False
        self.selected_mod: Optional[ModInfo] = None
        
        # Icon cache
        self.icon_cache: Dict[str, ImageTk.PhotoImage] = {}
        
        # Variables
        self.mods_folder = tk.StringVar(value=self.settings.get("last_mods_dir", ""))
        self.online_hints = tk.BooleanVar(value=self.settings.get("online_hints_enabled", True))
        self.show_info = tk.BooleanVar(value=True)
        self.show_warnings = tk.BooleanVar(value=True)
        self.show_errors = tk.BooleanVar(value=True)
        self.loader_filter = tk.StringVar(value="All")
        self.search_text = tk.StringVar()
        
        # Bind search
        self.search_text.trace('w', self._on_search_changed)
        self.show_info.trace('w', self._on_filter_changed)
        self.show_warnings.trace('w', self._on_filter_changed)
        self.show_errors.trace('w', self._on_filter_changed)
        self.loader_filter.trace('w', self._on_filter_changed)
        
        self.create_widgets()
        self.restore_window_state()
        
        # Bind window close
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
    def create_widgets(self):
        """Create the main GUI layout."""
        # Configure root grid
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(1, weight=1)
        
        # Create toolbar
        self.create_toolbar()
        
        # Create main content area
        self.create_main_content()
        
        # Create status bar
        self.create_status_bar()
    
    def create_toolbar(self):
        """Create the top toolbar."""
        toolbar_frame = ttk.Frame(self.root)
        toolbar_frame.grid(row=0, column=0, sticky="ew", padx=5, pady=5)
        toolbar_frame.columnconfigure(1, weight=1)
        
        # Mods folder selection
        ttk.Label(toolbar_frame, text="Mods Folder:").grid(row=0, column=0, padx=(0, 5))
        
        folder_frame = ttk.Frame(toolbar_frame)
        folder_frame.grid(row=0, column=1, sticky="ew", padx=(0, 10))
        folder_frame.columnconfigure(0, weight=1)
        
        self.folder_entry = ttk.Entry(folder_frame, textvariable=self.mods_folder)
        self.folder_entry.grid(row=0, column=0, sticky="ew", padx=(0, 5))
        
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).grid(row=0, column=1)
        
        # Action buttons
        button_frame = ttk.Frame(toolbar_frame)
        button_frame.grid(row=0, column=2, padx=(10, 0))
        
        self.analyze_btn = ttk.Button(button_frame, text="Analyze", command=self.start_analysis)
        self.analyze_btn.grid(row=0, column=0, padx=2)
        
        ttk.Button(button_frame, text="Export Report", command=self.export_report).grid(row=0, column=1, padx=2)
        ttk.Button(button_frame, text="Clear Cache", command=self.clear_cache).grid(row=0, column=2, padx=2)
        ttk.Button(button_frame, text="JVM Settings", command=self.show_jvm_dialog).grid(row=0, column=3, padx=2)
        
        # Online hints toggle
        ttk.Checkbutton(button_frame, text="Online Hints (Modrinth)", 
                       variable=self.online_hints, command=self.save_settings).grid(row=0, column=4, padx=(10, 0))
    
    def create_main_content(self):
        """Create the main content area with panels."""
        main_frame = ttk.Frame(self.root)
        main_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=(0, 5))
        main_frame.columnconfigure(1, weight=2)
        main_frame.rowconfigure(0, weight=1)
        
        # Left panel - mod list
        self.create_left_panel(main_frame)
        
        # Right panel - details
        self.create_right_panel(main_frame)
    
    def create_left_panel(self, parent):
        """Create left panel with mod list and filters."""
        left_frame = ttk.LabelFrame(parent, text="Mods", padding=5)
        left_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 5))
        left_frame.columnconfigure(0, weight=1)
        left_frame.rowconfigure(2, weight=1)
        
        # Search and filters
        search_frame = ttk.Frame(left_frame)
        search_frame.grid(row=0, column=0, sticky="ew", pady=(0, 5))
        search_frame.columnconfigure(1, weight=1)
        
        ttk.Label(search_frame, text="Search:").grid(row=0, column=0, padx=(0, 5))
        ttk.Entry(search_frame, textvariable=self.search_text).grid(row=0, column=1, sticky="ew")
        
        # Filter frame
        filter_frame = ttk.Frame(left_frame)
        filter_frame.grid(row=1, column=0, sticky="ew", pady=(0, 5))
        
        ttk.Label(filter_frame, text="Show:").grid(row=0, column=0, padx=(0, 5))
        ttk.Checkbutton(filter_frame, text="Info", variable=self.show_info).grid(row=0, column=1, padx=2)
        ttk.Checkbutton(filter_frame, text="Warnings", variable=self.show_warnings).grid(row=0, column=2, padx=2)
        ttk.Checkbutton(filter_frame, text="Errors", variable=self.show_errors).grid(row=0, column=3, padx=2)
        
        ttk.Label(filter_frame, text="Loader:").grid(row=0, column=4, padx=(10, 5))
        loader_combo = ttk.Combobox(filter_frame, textvariable=self.loader_filter, width=10,
                                   values=["All", "fabric", "quilt", "forge", "neoforge", "unknown"], state="readonly")
        loader_combo.grid(row=0, column=5, padx=2)
        
        # Mod treeview
        self.create_mod_treeview(left_frame)
        
        # Action buttons
        self.create_action_buttons(left_frame)
    
    def create_mod_treeview(self, parent):
        """Create the mod list treeview."""
        tree_frame = ttk.Frame(parent)
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Create treeview with columns
        columns = ("name", "version", "loader", "mc_version", "status")
        self.mod_tree = ttk.Treeview(tree_frame, columns=columns, show="tree headings", height=15)
        
        # Configure columns
        self.mod_tree.column("#0", width=40, minwidth=40)  # Icon column
        self.mod_tree.column("name", width=200, minwidth=150)
        self.mod_tree.column("version", width=80, minwidth=60)
        self.mod_tree.column("loader", width=80, minwidth=60)
        self.mod_tree.column("mc_version", width=100, minwidth=80)
        self.mod_tree.column("status", width=80, minwidth=60)
        
        # Configure headings
        self.mod_tree.heading("#0", text="")
        self.mod_tree.heading("name", text="Name")
        self.mod_tree.heading("version", text="Version")
        self.mod_tree.heading("loader", text="Loader")
        self.mod_tree.heading("mc_version", text="MC Version")
        self.mod_tree.heading("status", text="Status")
        
        # Scrollbar
        scrollbar_y = ttk.Scrollbar(tree_frame, orient="vertical", command=self.mod_tree.yview)
        scrollbar_y.grid(row=0, column=1, sticky="ns")
        self.mod_tree.configure(yscrollcommand=scrollbar_y.set)
        
        scrollbar_x = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.mod_tree.xview)
        scrollbar_x.grid(row=1, column=0, sticky="ew")
        self.mod_tree.configure(xscrollcommand=scrollbar_x.set)
        
        self.mod_tree.grid(row=0, column=0, sticky="nsew")
        
        # Bind events
        self.mod_tree.bind("<<TreeviewSelect>>", self.on_mod_selected)
        self.mod_tree.bind("<Button-3>", self.show_context_menu)  # Right click
        
        # Create context menu
        self.create_context_menu()
    
    def create_action_buttons(self, parent):
        """Create action buttons below the mod list."""
        action_frame = ttk.Frame(parent)
        action_frame.grid(row=3, column=0, sticky="ew", pady=(5, 0))
        
        self.disable_selected_btn = ttk.Button(action_frame, text="Disable Selected", 
                                             command=self.disable_selected_mod, state="disabled")
        self.disable_selected_btn.grid(row=0, column=0, padx=2, pady=2)
        
        self.disable_duplicates_btn = ttk.Button(action_frame, text="Disable Duplicates", 
                                               command=self.disable_duplicates, state="disabled")
        self.disable_duplicates_btn.grid(row=0, column=1, padx=2, pady=2)
        
        self.disable_conflicts_btn = ttk.Button(action_frame, text="Disable Conflicts", 
                                              command=self.disable_conflicts, state="disabled")
        self.disable_conflicts_btn.grid(row=1, column=0, padx=2, pady=2)
        
        self.disable_errors_btn = ttk.Button(action_frame, text="Disable All Errors", 
                                           command=self.disable_all_errors, state="disabled")
        self.disable_errors_btn.grid(row=1, column=1, padx=2, pady=2)
    
    def create_right_panel(self, parent):
        """Create right panel with mod details."""
        right_frame = ttk.LabelFrame(parent, text="Mod Details", padding=5)
        right_frame.grid(row=0, column=1, sticky="nsew")
        right_frame.columnconfigure(0, weight=1)
        right_frame.rowconfigure(1, weight=1)
        
        # Mod info frame
        info_frame = ttk.Frame(right_frame)
        info_frame.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        info_frame.columnconfigure(1, weight=1)
        
        # Mod icon and basic info
        self.mod_icon_label = ttk.Label(info_frame)
        self.mod_icon_label.grid(row=0, column=0, rowspan=3, padx=(0, 10))
        
        self.mod_name_label = ttk.Label(info_frame, text="Select a mod to view details", font=("TkDefaultFont", 12, "bold"))
        self.mod_name_label.grid(row=0, column=1, sticky="w")
        
        self.mod_version_label = ttk.Label(info_frame, text="")
        self.mod_version_label.grid(row=1, column=1, sticky="w")
        
        self.mod_loader_label = ttk.Label(info_frame, text="")
        self.mod_loader_label.grid(row=2, column=1, sticky="w")
        
        # Description and issues
        details_notebook = ttk.Notebook(right_frame)
        details_notebook.grid(row=1, column=0, sticky="nsew")
        
        # Description tab
        desc_frame = ttk.Frame(details_notebook)
        details_notebook.add(desc_frame, text="Description")
        
        self.description_text = scrolledtext.ScrolledText(desc_frame, wrap=tk.WORD, height=10, state="disabled")
        self.description_text.pack(fill="both", expand=True)
        
        # Issues tab
        issues_frame = ttk.Frame(details_notebook)
        details_notebook.add(issues_frame, text="Issues")
        
        self.issues_text = scrolledtext.ScrolledText(issues_frame, wrap=tk.WORD, height=10, state="disabled")
        self.issues_text.pack(fill="both", expand=True)
    
    def create_context_menu(self):
        """Create context menu for mod tree."""
        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Disable Mod", command=self.disable_selected_mod)
        self.context_menu.add_command(label="Open in Explorer", command=self.open_selected_in_explorer)
    
    def create_status_bar(self):
        """Create status bar at bottom."""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.grid(row=2, column=0, sticky="ew", padx=5, pady=(0, 5))
        self.status_frame.columnconfigure(0, weight=1)
        
        self.status_label = ttk.Label(self.status_frame, text="Ready")
        self.status_label.grid(row=0, column=0, sticky="w")
        
        self.progress_bar = ttk.Progressbar(self.status_frame, mode="indeterminate")
        self.progress_bar.grid(row=0, column=1, sticky="e", padx=(10, 0))
    def browse_folder(self):
        """Browse for mods folder."""
        folder = filedialog.askdirectory(
            title="Select Mods Folder",
            initialdir=self.mods_folder.get() or Path.home()
        )
        if folder:
            self.mods_folder.set(folder)
            add_recent_mods_dir(folder)
            self.save_settings()
    
    def save_settings(self):
        """Save current settings."""
        self.settings["last_mods_dir"] = self.mods_folder.get()
        self.settings["online_hints_enabled"] = self.online_hints.get()
        save_settings(self.settings)
    
    def start_analysis(self):
        """Start mod analysis in background thread."""
        if not self.mods_folder.get():
            messagebox.showerror("Error", "Please select a mods folder first.")
            return
        
        mods_path = Path(self.mods_folder.get())
        if not mods_path.exists():
            messagebox.showerror("Error", "Selected mods folder does not exist.")
            return
        
        if self.analysis_running:
            return
        
        # Clear previous results
        self.mods.clear()
        self.analysis_result = None
        self.selected_mod = None
        self.clear_mod_list()
        self.clear_details()
        
        # Start analysis
        self.analysis_running = True
        self.analyze_btn.config(state="disabled", text="Analyzing...")
        self.progress_bar.start()
        self.status_label.config(text="Scanning mods...")
        
        # Run in background thread
        thread = threading.Thread(target=self._analysis_worker, args=(mods_path,), daemon=True)
        thread.start()
    
    def _analysis_worker(self, mods_path: Path):
        """Background worker for analysis."""
        try:
            def progress_callback(filename, current, total):
                self.root.after(0, lambda: self.status_label.config(
                    text=f"Scanning {current}/{total}: {filename}"
                ))
            
            # Scan mods
            self.mods = scan_mods_directory(mods_path, progress_callback)
            
            self.root.after(0, lambda: self.status_label.config(text="Enriching mod data..."))
            
            # Enrich with online data if enabled
            if self.online_hints.get():
                for i, mod in enumerate(self.mods):
                    enrich_mod_info(mod, self.online_hints.get())
                    self.root.after(0, lambda i=i: self.status_label.config(
                        text=f"Enriching mod data... {i+1}/{len(self.mods)}"
                    ))
            
            self.root.after(0, lambda: self.status_label.config(text="Analyzing mods..."))
            
            # Analyze mods
            self.analysis_result = analyze_mods(self.mods)
            
            # Update UI on main thread
            self.root.after(0, self._analysis_complete)
            
        except Exception as e:
            self.root.after(0, lambda: self._analysis_error(str(e)))
    
    def _analysis_complete(self):
        """Called when analysis is complete."""
        self.analysis_running = False
        self.analyze_btn.config(state="normal", text="Analyze")
        self.progress_bar.stop()
        
        # Update UI
        self.update_mod_list()
        self.update_action_buttons()
        
        # Show summary
        if self.analysis_result:
            error_count = sum(1 for issue in self.analysis_result.issues 
                            if issue.get_severity_enum() == Severity.ERROR)
            warning_count = sum(1 for issue in self.analysis_result.issues 
                              if issue.get_severity_enum() == Severity.WARNING)
            info_count = sum(1 for issue in self.analysis_result.issues 
                           if issue.get_severity_enum() == Severity.INFO)
            
            status_text = f"Analysis complete: {len(self.mods)} mods, {error_count} errors, {warning_count} warnings, {info_count} info"
            self.status_label.config(text=status_text)
            
            if error_count > 0:
                messagebox.showwarning("Issues Found", 
                    f"Analysis found {error_count} errors and {warning_count} warnings. "
                    f"Check the mod details for more information.")
        else:
            self.status_label.config(text="Analysis failed")
    
    def _analysis_error(self, error_msg: str):
        """Called when analysis fails."""
        self.analysis_running = False
        self.analyze_btn.config(state="normal", text="Analyze")
        self.progress_bar.stop()
        self.status_label.config(text="Analysis failed")
        messagebox.showerror("Analysis Error", f"Failed to analyze mods: {error_msg}")
    
    def clear_mod_list(self):
        """Clear the mod list."""
        for item in self.mod_tree.get_children():
            self.mod_tree.delete(item)
    
    def update_mod_list(self):
        """Update the mod list display."""
        self.clear_mod_list()
        
        if not self.mods:
            return
        
        # Apply filters
        self._apply_filters()
        
        # Populate tree
        for mod in self.filtered_mods:
            self._add_mod_to_tree(mod)
    
    def _apply_filters(self):
        """Apply search and filter criteria."""
        if not self.analysis_result:
            self.filtered_mods = self.mods.copy()
            self.filtered_issues = []
            return
        
        # Get issues for each mod
        mod_issues = {}
        for issue in self.analysis_result.issues:
            mod_files = [f.strip() for f in issue.mod_file.split(",")]
            for mod_file in mod_files:
                if mod_file not in mod_issues:
                    mod_issues[mod_file] = []
                mod_issues[mod_file].append(issue)
        
        # Filter mods
        filtered_mods = []
        filtered_issues = []
        
        search_lower = self.search_text.get().lower()
        loader_filter = self.loader_filter.get()
        
        for mod in self.mods:
            # Apply search filter
            if search_lower:
                mod_name = (mod.name or mod.modid or mod.file_name).lower()
                if search_lower not in mod_name:
                    continue
            
            # Apply loader filter
            if loader_filter != "All":
                if mod.loader != loader_filter:
                    continue
            
            # Check if mod has issues matching severity filters
            mod_issues_list = mod_issues.get(mod.file_name, [])
            has_visible_issues = False
            
            for issue in mod_issues_list:
                severity = issue.get_severity_enum()
                if ((severity == Severity.ERROR and self.show_errors.get()) or
                    (severity == Severity.WARNING and self.show_warnings.get()) or
                    (severity == Severity.INFO and self.show_info.get())):
                    has_visible_issues = True
                    filtered_issues.append(issue)
            
            # Include mod if it has no issues or has visible issues
            if not mod_issues_list or has_visible_issues:
                filtered_mods.append(mod)
        
        self.filtered_mods = filtered_mods
        self.filtered_issues = filtered_issues
    
    def _add_mod_to_tree(self, mod: ModInfo):
        """Add a mod to the tree view."""
        # Get mod status based on issues
        status = self._get_mod_status(mod)
        status_color = self._get_status_color(status)
        
        # Get or create icon
        icon = self._get_mod_icon(mod)
        
        # Prepare display values
        name = mod.name or mod.modid or mod.file_name
        version = mod.version or "Unknown"
        loader = mod.loader or "Unknown"
        mc_versions = ", ".join(mod.minecraft_versions) if mod.minecraft_versions else "Unknown"
        
        # Insert into tree
        item_id = self.mod_tree.insert("", "end", 
                                      image=icon,
                                      values=(name, version, loader, mc_versions, status),
                                      tags=(status_color,))
        
        # Configure colors
        self.mod_tree.set(item_id, "#0", "")  # Icon column
        
        # Store mod reference
        self.mod_tree.set(item_id, "mod_ref", mod)
    
    def _get_mod_status(self, mod: ModInfo) -> str:
        """Get status string for a mod based on its issues."""
        if not self.analysis_result:
            return "OK"
        
        mod_issues = [issue for issue in self.analysis_result.issues 
                     if mod.file_name in issue.mod_file]
        
        if not mod_issues:
            return "OK"
        
        # Find highest severity
        severities = [issue.get_severity_enum() for issue in mod_issues]
        
        if Severity.ERROR in severities:
            return "ERROR"
        elif Severity.WARNING in severities:
            return "WARNING"
        elif Severity.INFO in severities:
            return "INFO"
        
        return "OK"
    
    def _get_status_color(self, status: str) -> str:
        """Get color tag for status."""
        colors = {
            "OK": "ok_color",
            "INFO": "info_color", 
            "WARNING": "warning_color",
            "ERROR": "error_color"
        }
        return colors.get(status, "ok_color")
    
    def _get_mod_icon(self, mod: ModInfo) -> str:
        """Get or create icon for mod."""
        if not ImageTk:
            return ""
        
        # Use cached icon if available
        cache_key = mod.fingerprint_sha256 or mod.file_name
        if cache_key in self.icon_cache:
            return self.icon_cache[cache_key]
        
        # Create icon
        if mod.icon_image:
            pil_icon = mod.icon_image.resize((16, 16), Image.Resampling.LANCZOS)
        else:
            pil_icon = create_placeholder_icon((16, 16))
        
        tk_icon = ImageTk.PhotoImage(pil_icon)
        self.icon_cache[cache_key] = tk_icon
        
        return tk_icon
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=row, column=0, columnspan=2, pady=10)
        
        self.run_button = ttk.Button(buttons_frame, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        row += 1
        
        # Log frame
        log_frame = ttk.LabelFrame(main_frame, text="Output Log", padding="5")
        log_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10)
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(row, weight=1)
        
        # Output text
        self.output_text = scrolledtext.ScrolledText(log_frame, height=15, state=tk.DISABLED)
        self.output_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Progress bar
        row += 1
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=5)
        
    def browse_folder(self):
        folder = filedialog.askdirectory(title="Select Mods Folder")
        if folder:
            self.mods_folder.set(folder)
    
    def log_message(self, message):
        """Add message to the output log"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)
        self.output_text.config(state=tk.DISABLED)
        self.root.update_idletasks()
    
    def clear_log(self):
        """Clear the output log"""
        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state=tk.DISABLED)
    
    def find_doctor_script(self):
        """Find the modpack doctor script, trying both possible names"""
        script_dir = Path(__file__).parent
        
        # When running as a PyInstaller bundle, use the temp directory
        if getattr(sys, 'frozen', False):
            script_dir = Path(sys._MEIPASS)
        
        # Try both possible names for compatibility
        candidates = [
            script_dir / "modpack_doctor_Version3.py",
            script_dir / "modpack_doctor.py"
        ]
        
        for candidate in candidates:
            if candidate.exists():
                return candidate
        
        # If not found in script directory, try current working directory
        for name in ["modpack_doctor_Version3.py", "modpack_doctor.py"]:
            candidate = Path.cwd() / name
            if candidate.exists():
                return candidate
        
        return None
    
    def build_command(self, doctor_script):
        """Build the command line arguments for the doctor script"""
        if not self.mods_folder.get():
            raise ValueError("Please select a mods folder")
        
        # Use sys.executable to ensure we use the same Python interpreter
        cmd = [sys.executable, str(doctor_script), self.mods_folder.get()]
        
        if self.online.get():
            cmd.append("--online")
        
        if self.curseforge.get():
            cmd.append("--curseforge")
            if self.curseforge_key.get():
                cmd.extend(["--curseforge-key", self.curseforge_key.get()])
        
        if self.mc_version.get():
            cmd.extend(["--mc", self.mc_version.get()])
        
        if self.loader.get():
            cmd.extend(["--loader", self.loader.get()])
        
        if self.ram_gb.get():
            try:
                float(self.ram_gb.get())
                cmd.extend(["--ram-gb", self.ram_gb.get()])
            except ValueError:
                raise ValueError("RAM must be a valid number")
        
        if self.no_db_update.get():
            cmd.append("--no-db-update")
        
        return cmd
    
    def run_analysis_thread(self):
        """Run the analysis in a separate thread"""
        try:
            doctor_script = self.find_doctor_script()
            if not doctor_script:
                self.log_message("ERROR: Could not find modpack doctor script!")
                self.log_message("Looking for: modpack_doctor_Version3.py or modpack_doctor.py")
                return
            
            self.log_message(f"Found doctor script: {doctor_script}")
            
            cmd = self.build_command(doctor_script)
            self.log_message(f"Running command: {' '.join(cmd)}")
            self.log_message("-" * 50)
            
            # Start the process
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                universal_newlines=True,
                bufsize=1
            )
            
            # Read output line by line
            for line in iter(self.process.stdout.readline, ''):
                if line:
                    self.log_message(line.rstrip())
                if self.process.poll() is not None:
                    break
            
            # Wait for process to complete
            self.process.wait()
            
            if self.process.returncode == 0:
                self.log_message("-" * 50)
                self.log_message("Analysis completed successfully!")
                
                # Try to find and open the generated report
                mods_path = Path(self.mods_folder.get())
                report_path = mods_path / "modpack_doctor_output" / "modpack_report.md"
                
                if report_path.exists():
                    self.log_message(f"Opening report: {report_path}")
                    self.open_file(report_path)
                else:
                    self.log_message("Report file not found at expected location")
            else:
                self.log_message(f"Analysis failed with exit code: {self.process.returncode}")
                
        except ValueError as e:
            self.log_message(f"ERROR: {e}")
        except Exception as e:
            self.log_message(f"ERROR: {e}")
        finally:
            # Re-enable UI
            self.root.after(0, self.analysis_finished)
    
    def open_file(self, file_path):
        """Open a file with the default system application"""
        try:
            if platform.system() == 'Windows':
                os.startfile(file_path)
            elif platform.system() == 'Darwin':  # macOS
                subprocess.run(['open', file_path])
            else:  # Linux and others
                subprocess.run(['xdg-open', file_path])
        except Exception as e:
            self.log_message(f"Could not open file: {e}")
            # Fallback: show file location
            self.log_message(f"Report saved to: {file_path}")
    
    def run_analysis(self):
        """Start the analysis"""
        if not self.mods_folder.get():
            messagebox.showerror("Error", "Please select a mods folder")
            return
        
        # Disable UI
        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()
        
        # Clear previous output
        self.clear_log()
        
        # Start analysis in background thread
        thread = threading.Thread(target=self.run_analysis_thread, daemon=True)
        thread.start()
    
    def stop_analysis(self):
        """Stop the running analysis"""
        if self.process:
            try:
                self.process.terminate()
                self.log_message("Analysis stopped by user")
            except Exception as e:
                self.log_message(f"Error stopping process: {e}")
        
        self.analysis_finished()
    
    def analysis_finished(self):
        """Re-enable UI after analysis"""
        self.run_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.process = None
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()


def main():
    # Create and run the GUI
    app = ModpackDoctorGUI()
    app.run()


if __name__ == "__main__":
    main()