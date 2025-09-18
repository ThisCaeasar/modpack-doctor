#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Modpack Doctor GUI - Advanced desktop application for analyzing Minecraft mod packs.
"""

import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path
import webbrowser
from typing import List, Optional, Dict, Any

# Add the project root to Python path for imports
project_root = Path(__file__).parent
if str(project_root) not in sys.path:
    sys.path.insert(0, str(project_root))

from moddoctor.core.model import ModInfo, Severity, AnalysisResult
from moddoctor.core.scan import scan_mods_folder
from moddoctor.core.analyzer import ModAnalyzer
from moddoctor.core.fixes import (
    disable_mod, disable_duplicates, disable_conflicts, 
    disable_all_errors, open_in_explorer, is_mod_disabled
)
from moddoctor.core.hardware import get_hardware_info
from moddoctor.core.report import export_analysis_report
from moddoctor.util.cache import CacheManager
from moddoctor.integrations.modrinth import enrich_mods_with_modrinth
from moddoctor.settings import Settings

try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False


class ModpackDoctorGUI:
    """Main GUI application for Modpack Doctor."""
    
    def __init__(self):
        """Initialize the GUI application."""
        self.root = tk.Tk()
        self.root.title("Modpack Doctor")
        self.root.geometry("1200x800")
        self.root.minsize(800, 600)
        
        # Initialize components
        self.settings = Settings()
        self.cache_manager = CacheManager() if self.settings.is_cache_enabled() else None
        self.analyzer = ModAnalyzer()
        
        # Data
        self.mods: List[ModInfo] = []
        self.analysis_result: Optional[AnalysisResult] = None
        self.current_mod: Optional[ModInfo] = None
        self.filtered_mods: List[ModInfo] = []
        
        # Threading
        self.analysis_thread: Optional[threading.Thread] = None
        self.analysis_running = False
        
        # Create GUI components
        self.create_widgets()
        self.setup_shortcuts()
        self.load_settings()
        
        # Setup column sorting
        self.sort_column = "name"
        self.sort_reverse = False
    
    def create_widgets(self):
        """Create the main GUI widgets."""
        # Main container
        main_container = ttk.Frame(self.root)
        main_container.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Create toolbar
        self.create_toolbar(main_container)
        
        # Create main panels
        self.create_main_panels(main_container)
        
        # Create status bar
        self.create_status_bar(main_container)
        
    def create_toolbar(self, parent):
        """Create the toolbar with main actions."""
        toolbar_frame = ttk.Frame(parent)
        toolbar_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Folder selection
        folder_frame = ttk.LabelFrame(toolbar_frame, text="Mods Directory", padding=5)
        folder_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        folder_entry_frame = ttk.Frame(folder_frame)
        folder_entry_frame.pack(fill=tk.X)
        
        self.folder_var = tk.StringVar(value=self.settings.get_last_mods_dir())
        self.folder_entry = ttk.Entry(folder_entry_frame, textvariable=self.folder_var)
        self.folder_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(folder_entry_frame, text="Browse", 
                  command=self.browse_folder).pack(side=tk.RIGHT)
        
        # Main actions
        actions_frame = ttk.LabelFrame(toolbar_frame, text="Actions", padding=5)
        actions_frame.pack(side=tk.RIGHT, padx=(5, 0))
        
        ttk.Button(actions_frame, text="Analyze", 
                  command=self.start_analysis).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Export Report", 
                  command=self.export_report).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="Clear Cache", 
                  command=self.clear_cache).pack(side=tk.LEFT, padx=2)
        ttk.Button(actions_frame, text="JVM Settings", 
                  command=self.show_jvm_dialog).pack(side=tk.LEFT, padx=2)
        
        # Settings
        settings_frame = ttk.Frame(toolbar_frame)
        settings_frame.pack(side=tk.RIGHT, padx=(5, 0))
        
        self.online_var = tk.BooleanVar(value=self.settings.is_online_enabled())
        self.online_check = ttk.Checkbutton(settings_frame, text="Online hints (Modrinth)", 
                                          variable=self.online_var,
                                          command=self.toggle_online)
        self.online_check.pack()
    
    def create_main_panels(self, parent):
        """Create the main content panels."""
        # Create horizontal paned window
        paned = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, pady=(0, 5))
        
        # Left panel - Mod list
        self.create_mod_list_panel(paned)
        
        # Right panel - Details
        self.create_details_panel(paned)
        
        # Configure paned window
        paned.add(self.left_panel, weight=2)
        paned.add(self.right_panel, weight=1)
    
    def create_mod_list_panel(self, parent):
        """Create the left panel with mod list."""
        self.left_panel = ttk.Frame(parent)
        
        # Search and filters
        filter_frame = ttk.Frame(self.left_panel)
        filter_frame.pack(fill=tk.X, pady=(0, 5))
        
        # Search
        search_frame = ttk.Frame(filter_frame)
        search_frame.pack(fill=tk.X, pady=(0, 2))
        
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", self.on_search_changed)
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 0))
        search_entry.bind("<Return>", lambda e: self.filter_mods())
        
        # Filters
        filters_frame = ttk.Frame(filter_frame)
        filters_frame.pack(fill=tk.X)
        
        ttk.Label(filters_frame, text="Severity:").pack(side=tk.LEFT)
        self.severity_filter = ttk.Combobox(filters_frame, width=10, state="readonly")
        self.severity_filter["values"] = ("All", "Error", "Warning", "Info", "OK")
        self.severity_filter.set("All")
        self.severity_filter.bind("<<ComboboxSelected>>", lambda e: self.filter_mods())
        self.severity_filter.pack(side=tk.LEFT, padx=(5, 10))
        
        ttk.Label(filters_frame, text="Loader:").pack(side=tk.LEFT)
        self.loader_filter = ttk.Combobox(filters_frame, width=10, state="readonly")
        self.loader_filter["values"] = ("All", "fabric", "forge", "quilt", "neoforge")
        self.loader_filter.set("All")
        self.loader_filter.bind("<<ComboboxSelected>>", lambda e: self.filter_mods())
        self.loader_filter.pack(side=tk.LEFT, padx=(5, 0))
        
        # Mod list with treeview
        list_frame = ttk.Frame(self.left_panel)
        list_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure treeview
        columns = ("name", "version", "loader", "mc_version", "status")
        self.mod_tree = ttk.Treeview(list_frame, columns=columns, show="tree headings", height=15)
        
        # Configure column headings
        self.mod_tree.heading("#0", text="Icon")
        self.mod_tree.heading("name", text="Name", command=lambda: self.sort_mods("name"))
        self.mod_tree.heading("version", text="Version", command=lambda: self.sort_mods("version"))
        self.mod_tree.heading("loader", text="Loader", command=lambda: self.sort_mods("loader"))
        self.mod_tree.heading("mc_version", text="MC Version", command=lambda: self.sort_mods("mc_version"))
        self.mod_tree.heading("status", text="Status", command=lambda: self.sort_mods("status"))
        
        # Configure column widths
        self.mod_tree.column("#0", width=50, minwidth=50)
        self.mod_tree.column("name", width=200, minwidth=150)
        self.mod_tree.column("version", width=100, minwidth=80)
        self.mod_tree.column("loader", width=80, minwidth=60)
        self.mod_tree.column("mc_version", width=100, minwidth=80)
        self.mod_tree.column("status", width=80, minwidth=60)
        
        # Configure tags for severity colors
        self.mod_tree.tag_configure("ok", background="#e8f5e8")
        self.mod_tree.tag_configure("info", background="#e8f0ff")
        self.mod_tree.tag_configure("warning", background="#fff5e8")
        self.mod_tree.tag_configure("error", background="#ffe8e8")
        
        # Scrollbar for treeview
        tree_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.mod_tree.yview)
        self.mod_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack treeview and scrollbar
        self.mod_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind events
        self.mod_tree.bind("<<TreeviewSelect>>", self.on_mod_selected)
        self.mod_tree.bind("<Button-3>", self.show_context_menu)  # Right click
        self.mod_tree.bind("<Double-1>", self.on_mod_double_clicked)
        
        # Action buttons
        actions_frame = ttk.Frame(self.left_panel)
        actions_frame.pack(fill=tk.X, pady=(5, 0))
        
        ttk.Button(actions_frame, text="Disable Selected", 
                  command=self.disable_selected).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(actions_frame, text="Disable Duplicates", 
                  command=self.disable_duplicates_action).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(actions_frame, text="Disable Conflicts", 
                  command=self.disable_conflicts_action).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(actions_frame, text="Disable All Errors", 
                  command=self.disable_errors_action).pack(side=tk.LEFT)
    
    def create_details_panel(self, parent):
        """Create the right panel with mod details."""
        self.right_panel = ttk.Frame(parent)
        
        # Details header
        header_frame = ttk.Frame(self.right_panel)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.details_title = ttk.Label(header_frame, text="Select a mod to view details", 
                                      font=("TkDefaultFont", 12, "bold"))
        self.details_title.pack()
        
        # Details content with scrolling
        details_frame = ttk.Frame(self.right_panel)
        details_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create scrolled text for details
        self.details_text = tk.Text(details_frame, wrap=tk.WORD, state=tk.DISABLED, 
                                   font=("TkDefaultFont", 9))
        details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, 
                                      command=self.details_text.yview)
        self.details_text.configure(yscrollcommand=details_scroll.set)
        
        self.details_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        details_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Action buttons
        actions_frame = ttk.Frame(self.right_panel)
        actions_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.disable_button = ttk.Button(actions_frame, text="Disable", 
                                        command=self.disable_current_mod, state=tk.DISABLED)
        self.disable_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.explorer_button = ttk.Button(actions_frame, text="Open in Explorer", 
                                         command=self.open_current_in_explorer, state=tk.DISABLED)
        self.explorer_button.pack(side=tk.LEFT, padx=(0, 5))
        
        self.homepage_button = ttk.Button(actions_frame, text="Open Homepage", 
                                         command=self.open_current_homepage, state=tk.DISABLED)
        self.homepage_button.pack(side=tk.LEFT)
    
    def create_status_bar(self, parent):
        """Create the status bar."""
        self.status_bar = ttk.Frame(parent)
        self.status_bar.pack(fill=tk.X)
        
        # Status label
        self.status_var = tk.StringVar(value="Ready")
        status_label = ttk.Label(self.status_bar, textvariable=self.status_var)
        status_label.pack(side=tk.LEFT)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(self.status_bar, variable=self.progress_var, 
                                           mode="determinate")
        self.progress_bar.pack(side=tk.RIGHT, padx=(10, 0))
    
    def setup_shortcuts(self):
        """Setup keyboard shortcuts."""
        self.root.bind("<Control-o>", lambda e: self.browse_folder())
        self.root.bind("<F5>", lambda e: self.start_analysis())
        self.root.bind("<Control-s>", lambda e: self.export_report())
        self.root.bind("<Control-q>", lambda e: self.quit_application())
        self.root.bind("<Delete>", lambda e: self.disable_selected())
    
    def load_settings(self):
        """Load settings and apply to GUI."""
        # Restore window geometry
        geometry = self.settings.get_window_geometry()
        if geometry:
            self.root.geometry(geometry)
        
        position = self.settings.get_window_position()
        if position:
            self.root.geometry(f"+{position}")
    
    def save_settings(self):
        """Save current settings."""
        # Save window geometry and position
        geometry = self.root.geometry()
        if "+" in geometry:
            size, position = geometry.split("+", 1)
            self.settings.set_window_geometry(size)
            self.settings.set_window_position(position)
        else:
            self.settings.set_window_geometry(geometry)
    
    # Event handlers
    def browse_folder(self):
        """Browse for mods folder."""
        initial_dir = self.folder_var.get() or self.settings.get_last_mods_dir()
        if not initial_dir:
            initial_dir = str(Path.home())
        
        folder = filedialog.askdirectory(
            title="Select Mods Directory",
            initialdir=initial_dir
        )
        
        if folder:
            self.folder_var.set(folder)
            self.settings.set_last_mods_dir(folder)
    
    def toggle_online(self):
        """Toggle online features."""
        self.settings.set_online_enabled(self.online_var.get())
    
    def start_analysis(self):
        """Start mod analysis in background thread."""
        if self.analysis_running:
            messagebox.showwarning("Analysis Running", "Analysis is already in progress.")
            return
        
        mods_dir = Path(self.folder_var.get())
        if not mods_dir.exists() or not mods_dir.is_dir():
            messagebox.showerror("Invalid Directory", "Please select a valid mods directory.")
            return
        
        self.analysis_running = True
        self.status_var.set("Starting analysis...")
        self.progress_var.set(0)
        self.progress_bar.configure(mode="indeterminate")
        self.progress_bar.start()
        
        # Disable UI elements during analysis
        self.disable_ui_during_analysis(True)
        
        # Start analysis in background thread
        self.analysis_thread = threading.Thread(
            target=self._run_analysis_background, 
            args=(mods_dir,)
        )
        self.analysis_thread.daemon = True
        self.analysis_thread.start()
    
    def _run_analysis_background(self, mods_dir: Path):
        """Run analysis in background thread."""
        try:
            # Update status
            self.root.after(0, lambda: self.status_var.set("Scanning mods..."))
            
            # Scan mods
            mods = scan_mods_folder(mods_dir, self.cache_manager)
            
            # Update status
            self.root.after(0, lambda: self.status_var.set(f"Found {len(mods)} mods. Enriching..."))
            
            # Enrich with Modrinth if enabled
            if self.online_var.get():
                enriched = enrich_mods_with_modrinth(mods, enabled=True)
                self.root.after(0, lambda: self.status_var.set(f"Enriched {enriched} mods. Analyzing..."))
            
            # Analyze mods
            self.root.after(0, lambda: self.status_var.set("Analyzing issues..."))
            analysis_result = self.analyzer.analyze_mods(mods)
            
            # Update UI on main thread
            self.root.after(0, lambda: self._analysis_completed(mods, analysis_result))
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            self.root.after(0, lambda: self._analysis_failed(error_msg))
    
    def _analysis_completed(self, mods: List[ModInfo], analysis_result: AnalysisResult):
        """Handle analysis completion on main thread."""
        self.mods = mods
        self.analysis_result = analysis_result
        
        # Update mod list
        self.populate_mod_list()
        
        # Update status
        error_count = sum(1 for mod in mods if mod.overall_severity == Severity.ERROR)
        warning_count = sum(1 for mod in mods if mod.overall_severity == Severity.WARNING)
        
        status_msg = f"Analysis complete: {len(mods)} mods"
        if error_count > 0:
            status_msg += f", {error_count} errors"
        if warning_count > 0:
            status_msg += f", {warning_count} warnings"
        
        self.status_var.set(status_msg)
        
        # Re-enable UI
        self.disable_ui_during_analysis(False)
        self.analysis_running = False
        
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_var.set(100)
    
    def _analysis_failed(self, error_msg: str):
        """Handle analysis failure on main thread."""
        self.status_var.set("Analysis failed")
        self.disable_ui_during_analysis(False)
        self.analysis_running = False
        
        self.progress_bar.stop()
        self.progress_bar.configure(mode="determinate")
        self.progress_var.set(0)
        
        messagebox.showerror("Analysis Failed", error_msg)
    
    def disable_ui_during_analysis(self, disabled: bool):
        """Disable/enable UI elements during analysis."""
        # This could be expanded to disable specific buttons
        pass
    
    def populate_mod_list(self):
        """Populate the mod list treeview."""
        # Clear existing items
        self.mod_tree.delete(*self.mod_tree.get_children())
        
        # Apply filters
        self.filter_mods()
    
    def filter_mods(self):
        """Filter and display mods based on current filters."""
        if not self.mods:
            return
        
        # Get filter values
        search_text = self.search_var.get().lower()
        severity_filter = self.severity_filter.get()
        loader_filter = self.loader_filter.get()
        
        # Filter mods
        filtered_mods = []
        for mod in self.mods:
            # Search filter
            if search_text:
                searchable_text = f"{mod.name or ''} {mod.modid or ''} {mod.file_name}".lower()
                if search_text not in searchable_text:
                    continue
            
            # Severity filter
            if severity_filter != "All":
                if severity_filter.lower() != mod.overall_severity.value:
                    continue
            
            # Loader filter
            if loader_filter != "All":
                if loader_filter != (mod.loader or "unknown"):
                    continue
            
            filtered_mods.append(mod)
        
        self.filtered_mods = filtered_mods
        
        # Sort mods
        self.sort_filtered_mods()
        
        # Clear and repopulate tree
        self.mod_tree.delete(*self.mod_tree.get_children())
        
        for mod in self.filtered_mods:
            self.add_mod_to_tree(mod)
    
    def sort_mods(self, column: str):
        """Sort mods by the specified column."""
        if self.sort_column == column:
            self.sort_reverse = not self.sort_reverse
        else:
            self.sort_column = column
            self.sort_reverse = False
        
        self.sort_filtered_mods()
        
        # Refresh display
        self.mod_tree.delete(*self.mod_tree.get_children())
        for mod in self.filtered_mods:
            self.add_mod_to_tree(mod)
    
    def sort_filtered_mods(self):
        """Sort the filtered mods list."""
        if not self.filtered_mods:
            return
        
        def get_sort_key(mod):
            if self.sort_column == "name":
                return (mod.name or mod.file_name).lower()
            elif self.sort_column == "version":
                return mod.version or ""
            elif self.sort_column == "loader":
                return mod.loader or ""
            elif self.sort_column == "mc_version":
                return ", ".join(mod.minecraft_versions) or ""
            elif self.sort_column == "status":
                return mod.overall_severity.value
            else:
                return ""
        
        self.filtered_mods.sort(key=get_sort_key, reverse=self.sort_reverse)
    
    def add_mod_to_tree(self, mod: ModInfo):
        """Add a mod to the treeview."""
        # Determine tag based on severity
        severity = mod.overall_severity
        tag = severity.value
        
        # Get display values
        name = mod.name or mod.file_name
        version = mod.version or ""
        loader = mod.loader or ""
        mc_version = ", ".join(mod.minecraft_versions) if mod.minecraft_versions else ""
        status = severity.value.title()
        
        # Add disabled indicator
        if is_mod_disabled(mod):
            name += " (Disabled)"
            status = "Disabled"
            tag = "disabled"
        
        # Insert into tree
        item = self.mod_tree.insert("", tk.END, text="", tags=(tag,),
                                   values=(name, version, loader, mc_version, status))
        
        # Store mod reference
        self.mod_tree.set(item, "mod_ref", mod)
    
    def on_search_changed(self, *args):
        """Handle search text change."""
        # Auto-filter after a short delay
        if hasattr(self, '_search_timer'):
            self.root.after_cancel(self._search_timer)
        self._search_timer = self.root.after(300, self.filter_mods)
    
    def on_mod_selected(self, event):
        """Handle mod selection in treeview."""
        selection = self.mod_tree.selection()
        if not selection:
            self.current_mod = None
            self.update_details_panel(None)
            return
        
        item = selection[0]
        # Get mod from tree item (simplified approach)
        values = self.mod_tree.item(item, "values")
        if values:
            mod_name = values[0].replace(" (Disabled)", "")
            # Find mod by name (not ideal but works for now)
            for mod in self.mods:
                if (mod.name or mod.file_name) == mod_name:
                    self.current_mod = mod
                    self.update_details_panel(mod)
                    break
    
    def on_mod_double_clicked(self, event):
        """Handle double-click on mod."""
        if self.current_mod:
            open_in_explorer(self.current_mod.path)
    
    def update_details_panel(self, mod: Optional[ModInfo]):
        """Update the details panel with mod information."""
        if not mod:
            self.details_title.config(text="Select a mod to view details")
            self.details_text.config(state=tk.NORMAL)
            self.details_text.delete(1.0, tk.END)
            self.details_text.config(state=tk.DISABLED)
            
            self.disable_button.config(state=tk.DISABLED)
            self.explorer_button.config(state=tk.DISABLED)
            self.homepage_button.config(state=tk.DISABLED)
            return
        
        # Update title
        title = mod.name or mod.file_name
        if is_mod_disabled(mod):
            title += " (Disabled)"
        self.details_title.config(text=title)
        
        # Update details text
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete(1.0, tk.END)
        
        details = []
        
        # Basic info
        if mod.version:
            details.append(f"Version: {mod.version}")
        if mod.loader:
            details.append(f"Loader: {mod.loader}")
        if mod.modid:
            details.append(f"Mod ID: {mod.modid}")
        if mod.authors:
            details.append(f"Authors: {', '.join(mod.authors)}")
        if mod.minecraft_versions:
            details.append(f"MC Versions: {', '.join(mod.minecraft_versions)}")
        
        if details:
            self.details_text.insert(tk.END, "\n".join(details) + "\n\n")
        
        # Description
        if mod.description:
            self.details_text.insert(tk.END, f"Description:\n{mod.description}\n\n")
        
        # Issues
        if mod.issues:
            self.details_text.insert(tk.END, "Issues:\n")
            for issue in mod.issues:
                severity_icon = {"error": "❌", "warning": "⚠️", "info": "ℹ️", "ok": "✅"}
                icon = severity_icon.get(issue.severity.value, "•")
                self.details_text.insert(tk.END, f"{icon} {issue.message}\n")
                if issue.suggestion:
                    self.details_text.insert(tk.END, f"   Suggestion: {issue.suggestion}\n")
            self.details_text.insert(tk.END, "\n")
        
        # File info
        file_info = []
        file_info.append(f"File: {mod.file_name}")
        file_info.append(f"Path: {mod.path}")
        
        self.details_text.insert(tk.END, "\n".join(file_info))
        
        self.details_text.config(state=tk.DISABLED)
        
        # Update buttons
        self.disable_button.config(state=tk.NORMAL)
        self.explorer_button.config(state=tk.NORMAL)
        
        if mod.homepage or mod.project_url:
            self.homepage_button.config(state=tk.NORMAL)
        else:
            self.homepage_button.config(state=tk.DISABLED)
    
    def show_context_menu(self, event):
        """Show context menu for mod."""
        # Select item under cursor
        item = self.mod_tree.identify_row(event.y)
        if item:
            self.mod_tree.selection_set(item)
            self.on_mod_selected(None)  # Update current mod
            
            # Create context menu
            context_menu = tk.Menu(self.root, tearoff=0)
            context_menu.add_command(label="Disable", command=self.disable_current_mod)
            context_menu.add_command(label="Open in Explorer", command=self.open_current_in_explorer)
            if self.current_mod and (self.current_mod.homepage or self.current_mod.project_url):
                context_menu.add_command(label="Open Homepage", command=self.open_current_homepage)
            
            try:
                context_menu.tk_popup(event.x_root, event.y_root)
            finally:
                context_menu.grab_release()
    
    # Action handlers
    def disable_selected(self):
        """Disable the currently selected mod."""
        if not self.current_mod:
            messagebox.showwarning("No Selection", "Please select a mod to disable.")
            return
        
        if disable_mod(self.current_mod):
            messagebox.showinfo("Success", f"Disabled {self.current_mod.name or self.current_mod.file_name}")
            self.refresh_mod_list()
        else:
            messagebox.showerror("Failed", "Failed to disable mod.")
    
    def disable_current_mod(self):
        """Disable the current mod."""
        self.disable_selected()
    
    def open_current_in_explorer(self):
        """Open current mod in file explorer."""
        if self.current_mod:
            open_in_explorer(self.current_mod.path)
    
    def open_current_homepage(self):
        """Open current mod's homepage."""
        if self.current_mod:
            url = self.current_mod.project_url or self.current_mod.homepage
            if url:
                webbrowser.open(url)
    
    def disable_duplicates_action(self):
        """Disable duplicate mods."""
        if not self.mods:
            messagebox.showwarning("No Mods", "No mods loaded.")
            return
        
        count = disable_duplicates(self.mods)
        if count > 0:
            messagebox.showinfo("Success", f"Disabled {count} duplicate mods.")
            self.refresh_mod_list()
        else:
            messagebox.showinfo("No Action", "No duplicate mods found.")
    
    def disable_conflicts_action(self):
        """Disable conflicting mods."""
        if not self.mods:
            messagebox.showwarning("No Mods", "No mods loaded.")
            return
        
        count = disable_conflicts(self.mods)
        if count > 0:
            messagebox.showinfo("Success", f"Disabled {count} conflicting mods.")
            self.refresh_mod_list()
        else:
            messagebox.showinfo("No Action", "No conflicting mods found.")
    
    def disable_errors_action(self):
        """Disable mods with errors."""
        if not self.mods:
            messagebox.showwarning("No Mods", "No mods loaded.")
            return
        
        count = disable_all_errors(self.mods)
        if count > 0:
            messagebox.showinfo("Success", f"Disabled {count} mods with errors.")
            self.refresh_mod_list()
        else:
            messagebox.showinfo("No Action", "No mods with errors found.")
    
    def refresh_mod_list(self):
        """Refresh the mod list after changes."""
        # Re-scan the directory to pick up changes
        mods_dir = Path(self.folder_var.get())
        if mods_dir.exists():
            self.start_analysis()
    
    def export_report(self):
        """Export analysis report to file."""
        if not self.analysis_result:
            messagebox.showwarning("No Analysis", "Please run analysis first.")
            return
        
        file_path = filedialog.asksaveasfilename(
            title="Export Report",
            defaultextension=".md",
            filetypes=[("Markdown files", "*.md"), ("All files", "*.*")]
        )
        
        if file_path:
            mods_dir = Path(self.folder_var.get()) if self.folder_var.get() else None
            if export_analysis_report(self.analysis_result, Path(file_path), mods_dir):
                messagebox.showinfo("Success", f"Report exported to {file_path}")
            else:
                messagebox.showerror("Failed", "Failed to export report.")
    
    def clear_cache(self):
        """Clear the mod cache."""
        if self.cache_manager:
            if messagebox.askyesno("Clear Cache", "Are you sure you want to clear the cache?"):
                self.cache_manager.clear_cache()
                messagebox.showinfo("Success", "Cache cleared.")
    
    def show_jvm_dialog(self):
        """Show JVM optimization dialog."""
        JVMDialog(self.root)
    
    def quit_application(self):
        """Quit the application."""
        self.save_settings()
        self.root.quit()
    
    def run(self):
        """Run the application."""
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.quit_application)
        
        # Start main loop
        self.root.mainloop()


class JVMDialog:
    """Dialog for JVM optimization settings."""
    
    def __init__(self, parent):
        """Initialize the JVM dialog."""
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("JVM Optimization")
        self.dialog.geometry("600x500")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Get hardware info
        self.hardware = get_hardware_info()
        
        self.create_widgets()
        
        # Center dialog
        self.dialog.geometry("+%d+%d" % (
            parent.winfo_rootx() + 50,
            parent.winfo_rooty() + 50
        ))
    
    def create_widgets(self):
        """Create dialog widgets."""
        main_frame = ttk.Frame(self.dialog, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Hardware info
        hw_frame = ttk.LabelFrame(main_frame, text="System Information", padding=10)
        hw_frame.pack(fill=tk.X, pady=(0, 10))
        
        hw_text = tk.Text(hw_frame, height=8, state=tk.DISABLED, font=("Courier", 9))
        hw_text.pack(fill=tk.BOTH, expand=True)
        
        hw_text.config(state=tk.NORMAL)
        hw_text.insert(1.0, self.hardware.get_hardware_summary())
        hw_text.config(state=tk.DISABLED)
        
        # RAM allocation
        ram_frame = ttk.LabelFrame(main_frame, text="RAM Allocation", padding=10)
        ram_frame.pack(fill=tk.X, pady=(0, 10))
        
        recommended_ram, reason = self.hardware.get_recommended_ram_allocation()
        
        ttk.Label(ram_frame, text=f"Recommended: {recommended_ram} GB ({reason})").pack()
        
        # RAM slider
        ram_control_frame = ttk.Frame(ram_frame)
        ram_control_frame.pack(fill=tk.X, pady=(10, 0))
        
        ttk.Label(ram_control_frame, text="Allocate:").pack(side=tk.LEFT)
        
        self.ram_var = tk.DoubleVar(value=recommended_ram)
        ram_scale = ttk.Scale(ram_control_frame, from_=1.0, to=min(32.0, self.hardware.memory_info["total_gb"]), 
                             variable=self.ram_var, orient=tk.HORIZONTAL, command=self.update_jvm_args)
        ram_scale.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5, 5))
        
        self.ram_label = ttk.Label(ram_control_frame, text=f"{recommended_ram:.1f} GB")
        self.ram_label.pack(side=tk.RIGHT)
        
        # JVM arguments
        jvm_frame = ttk.LabelFrame(main_frame, text="Generated JVM Arguments", padding=10)
        jvm_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        self.jvm_text = tk.Text(jvm_frame, wrap=tk.WORD, font=("Courier", 9))
        jvm_scroll = ttk.Scrollbar(jvm_frame, orient=tk.VERTICAL, command=self.jvm_text.yview)
        self.jvm_text.configure(yscrollcommand=jvm_scroll.set)
        
        self.jvm_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        jvm_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X)
        
        ttk.Button(button_frame, text="Copy to Clipboard", 
                  command=self.copy_to_clipboard).pack(side=tk.LEFT)
        ttk.Button(button_frame, text="Close", 
                  command=self.dialog.destroy).pack(side=tk.RIGHT)
        
        # Initialize JVM args
        self.update_jvm_args()
    
    def update_jvm_args(self, *args):
        """Update JVM arguments display."""
        ram_gb = self.ram_var.get()
        self.ram_label.config(text=f"{ram_gb:.1f} GB")
        
        jvm_args = self.hardware.generate_jvm_arguments(ram_gb)
        
        self.jvm_text.delete(1.0, tk.END)
        self.jvm_text.insert(1.0, jvm_args)
    
    def copy_to_clipboard(self):
        """Copy JVM arguments to clipboard."""
        jvm_args = self.jvm_text.get(1.0, tk.END).strip()
        self.dialog.clipboard_clear()
        self.dialog.clipboard_append(jvm_args)
        messagebox.showinfo("Copied", "JVM arguments copied to clipboard!")


def main():
    """Main entry point."""
    try:
        app = ModpackDoctorGUI()
        app.run()
    except Exception as e:
        import traceback
        error_msg = f"Fatal error: {str(e)}\n\n{traceback.format_exc()}"
        
        # Try to show error in GUI
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Fatal Error", error_msg)
            root.destroy()
        except Exception:
            # Fall back to console
            print(error_msg)
        
        sys.exit(1)


if __name__ == "__main__":
    main()