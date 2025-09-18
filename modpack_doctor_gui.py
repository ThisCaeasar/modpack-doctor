#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import subprocess
import threading
from pathlib import Path
import platform
import webbrowser
import json
import urllib.parse
from typing import Optional, Dict, Any


class ModpackDoctorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Modpack Doctor GUI")
        self.root.geometry("800x700")
        self.root.minsize(600, 500)
        
        # Variables
        self.mods_folder = tk.StringVar()
        self.analysis_mode = tk.StringVar(value="Quick")  # Quick or Deep
        self.curseforge_enabled = tk.BooleanVar()
        self.curseforge_key = tk.StringVar()
        self.mc_version = tk.StringVar()
        self.loader = tk.StringVar()
        self.ram_gb = tk.StringVar()
        self.no_db_update = tk.BooleanVar()
        self.crash_log_file = tk.StringVar()
        
        # Process tracking
        self.process = None
        self.output_file = None
        self.status_text = tk.StringVar(value="Idle")
        
        # Load saved settings
        self.settings_file = self.get_config_dir() / "modpack_doctor_settings.json"
        self.load_settings()
        
        self.create_widgets()
        
        # Save settings on close
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def get_config_dir(self) -> Path:
        """Get user config directory"""
        if platform.system() == "Windows":
            config_dir = Path(os.environ.get('APPDATA', '~')) / "ModpackDoctor"
        elif platform.system() == "Darwin":  # macOS
            config_dir = Path.home() / "Library" / "Application Support" / "ModpackDoctor"
        else:  # Linux and others
            config_dir = Path.home() / ".config" / "modpack-doctor"
        
        config_dir.mkdir(parents=True, exist_ok=True)
        return config_dir
    
    def load_settings(self):
        """Load settings from JSON file"""
        if self.settings_file.exists():
            try:
                with open(self.settings_file, 'r', encoding='utf-8') as f:
                    settings = json.load(f)
                
                self.mods_folder.set(settings.get('mods_folder', ''))
                self.analysis_mode.set(settings.get('analysis_mode', 'Quick'))
                self.mc_version.set(settings.get('mc_version', ''))
                self.loader.set(settings.get('loader', ''))
                self.ram_gb.set(settings.get('ram_gb', ''))
                self.curseforge_enabled.set(settings.get('curseforge_enabled', False))
                # Don't persist API key for security
            except Exception as e:
                print(f"Warning: Could not load settings: {e}")
    
    def save_settings(self):
        """Save settings to JSON file"""
        try:
            settings = {
                'mods_folder': self.mods_folder.get(),
                'analysis_mode': self.analysis_mode.get(),
                'mc_version': self.mc_version.get(),
                'loader': self.loader.get(),
                'ram_gb': self.ram_gb.get(),
                'curseforge_enabled': self.curseforge_enabled.get(),
                # Don't save API key for security
            }
            
            with open(self.settings_file, 'w', encoding='utf-8') as f:
                json.dump(settings, f, indent=2)
        except Exception as e:
            print(f"Warning: Could not save settings: {e}")
    
    def on_closing(self):
        """Handle window closing"""
        self.save_settings()
        self.root.destroy()
    
    def paste_from_clipboard(self):
        """Paste path from clipboard"""
        try:
            clipboard_text = self.root.clipboard_get()
            path = self.normalize_path(clipboard_text)
            if path:
                self.mods_folder.set(str(path))
        except tk.TclError:
            messagebox.showwarning("Warning", "Clipboard is empty or contains invalid data")
    
    def normalize_path(self, path_str: str) -> Optional[Path]:
        """Convert file:/// URLs to local paths and validate"""
        path_str = path_str.strip()
        
        # Handle file:/// URLs
        if path_str.startswith('file://'):
            try:
                parsed = urllib.parse.urlparse(path_str)
                if platform.system() == "Windows":
                    # On Windows, remove the leading slash from /C:/path
                    local_path = urllib.parse.unquote(parsed.path[1:])
                else:
                    local_path = urllib.parse.unquote(parsed.path)
                path_str = local_path
            except Exception:
                return None
        
        try:
            path = Path(path_str).expanduser().resolve()
            if path.exists() and path.is_dir():
                return path
        except Exception:
            pass
        
        return None
    
    def show_path_context_menu(self, event):
        """Show context menu for path entry"""
        context_menu = tk.Menu(self.root, tearoff=0)
        context_menu.add_command(label="Paste", command=self.paste_from_clipboard)
        try:
            context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            context_menu.grab_release()
    
    def open_report_folder(self):
        """Open the report output folder"""
        if not self.mods_folder.get():
            messagebox.showwarning("Warning", "Please select a mods folder first")
            return
        
        report_dir = Path(self.mods_folder.get()) / "modpack_doctor_output"
        if report_dir.exists():
            self.open_file(report_dir)
        else:
            messagebox.showinfo("Info", f"Report folder does not exist yet: {report_dir}")
    
    def export_mod_list(self):
        """Export a clean mod list to text file"""
        if not self.mods_folder.get():
            messagebox.showwarning("Warning", "Please select a mods folder first")
            return
        
        mods_dir = Path(self.mods_folder.get())
        if not mods_dir.exists():
            messagebox.showerror("Error", "Mods folder does not exist")
            return
        
        # Get all JAR files
        jar_files = sorted([f for f in mods_dir.iterdir() if f.suffix.lower() == ".jar"])
        
        if not jar_files:
            messagebox.showinfo("Info", "No JAR files found in mods folder")
            return
        
        # Create export content
        content = ["# Mod List Export", f"# Generated from: {mods_dir}", f"# Total mods: {len(jar_files)}", ""]
        
        for jar_file in jar_files:
            content.append(f"- {jar_file.name}")
        
        # Save to file
        output_dir = mods_dir / "modpack_doctor_output"
        output_dir.mkdir(exist_ok=True)
        export_file = output_dir / "mod_list.txt"
        
        try:
            with open(export_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(content))
            
            messagebox.showinfo("Success", f"Mod list exported to: {export_file}")
            self.open_file(export_file)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export mod list: {e}")
    
    def browse_crash_log(self):
        """Browse for crash log file"""
        file_path = filedialog.askopenfilename(
            title="Select Crash Log",
            filetypes=[
                ("Text files", "*.txt"),
                ("Log files", "*.log"),
                ("All files", "*.*")
            ]
        )
        if file_path:
            self.crash_log_file.set(file_path)
    
    def update_crash_log_label(self, *args):
        """Update crash log label when file changes"""
        file_path = self.crash_log_file.get()
        if file_path:
            self.crash_log_label.config(text=Path(file_path).name, foreground="black")
        else:
            self.crash_log_label.config(text="None selected", foreground="gray")
    
    def toggle_curseforge_key(self):
        """Show/hide CurseForge API key field"""
        if self.curseforge_enabled.get():
            self.curseforge_key_label.grid(row=1, column=0, sticky=tk.W, pady=2)
            self.curseforge_key_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=2)
        else:
            self.curseforge_key_label.grid_remove()
            self.curseforge_key_entry.grid_remove()
    
    def update_status(self, status: str):
        """Update status text"""
        self.status_text.set(status)
        self.root.update_idletasks()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        row = 0
        
        # Mods folder selection
        ttk.Label(main_frame, text="Mods Folder:").grid(row=row, column=0, sticky=tk.W, pady=2)
        folder_frame = ttk.Frame(main_frame)
        folder_frame.grid(row=row, column=1, sticky=(tk.W, tk.E), pady=2)
        folder_frame.columnconfigure(0, weight=1)
        
        self.path_entry = ttk.Entry(folder_frame, textvariable=self.mods_folder)
        self.path_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        self.path_entry.bind("<Button-3>", self.show_path_context_menu)  # Right-click context menu
        
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).grid(row=0, column=1, padx=2)
        ttk.Button(folder_frame, text="Paste", command=self.paste_from_clipboard).grid(row=0, column=2)
        
        row += 1
        
        # Quick action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=row, column=0, columnspan=2, pady=5)
        
        ttk.Button(action_frame, text="Open Report Folder", command=self.open_report_folder).pack(side=tk.LEFT, padx=5)
        ttk.Button(action_frame, text="Export Mod List", command=self.export_mod_list).pack(side=tk.LEFT, padx=5)
        
        row += 1
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="5")
        options_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        options_frame.columnconfigure(1, weight=1)
        
        opt_row = 0
        
        # Analysis mode
        ttk.Label(options_frame, text="Analysis Mode:").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        mode_frame = ttk.Frame(options_frame)
        mode_frame.grid(row=opt_row, column=1, sticky=tk.W, pady=2)
        
        ttk.Radiobutton(mode_frame, text="Quick (fast, offline)", variable=self.analysis_mode, value="Quick").pack(side=tk.LEFT, padx=5)
        ttk.Radiobutton(mode_frame, text="Deep (online lookups)", variable=self.analysis_mode, value="Deep").pack(side=tk.LEFT, padx=5)
        opt_row += 1
        
        # MC Version dropdown
        ttk.Label(options_frame, text="Minecraft Version:").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        mc_combo = ttk.Combobox(options_frame, textvariable=self.mc_version, width=15,
                               values=["Auto", "1.21.1", "1.21", "1.20.1", "1.19.4"], state="readonly")
        mc_combo.grid(row=opt_row, column=1, sticky=tk.W, pady=2)
        opt_row += 1
        
        # Loader dropdown
        ttk.Label(options_frame, text="Loader:").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        loader_combo = ttk.Combobox(options_frame, textvariable=self.loader, width=15,
                                   values=["Auto", "neoforge", "forge", "fabric", "quilt"], state="readonly")
        loader_combo.grid(row=opt_row, column=1, sticky=tk.W, pady=2)
        opt_row += 1
        
        # CurseForge checkbox and key (initially hidden)
        self.curseforge_frame = ttk.Frame(options_frame)
        self.curseforge_frame.grid(row=opt_row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        self.curseforge_frame.columnconfigure(1, weight=1)
        
        ttk.Checkbutton(self.curseforge_frame, text="Use CurseForge (optional)", 
                       variable=self.curseforge_enabled, command=self.toggle_curseforge_key).grid(row=0, column=0, columnspan=2, sticky=tk.W)
        
        self.curseforge_key_label = ttk.Label(self.curseforge_frame, text="API Key:")
        self.curseforge_key_entry = ttk.Entry(self.curseforge_frame, textvariable=self.curseforge_key, show="*")
        
        opt_row += 1
        
        # Crash log upload
        ttk.Label(options_frame, text="Crash Log:").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        crash_frame = ttk.Frame(options_frame)
        crash_frame.grid(row=opt_row, column=1, sticky=(tk.W, tk.E), pady=2)
        crash_frame.columnconfigure(0, weight=1)
        
        self.crash_log_label = ttk.Label(crash_frame, text="None selected", foreground="gray")
        self.crash_log_label.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(crash_frame, text="Browse...", command=self.browse_crash_log).grid(row=0, column=1)
        
        # Update crash log label when file changes
        self.crash_log_file.trace("w", self.update_crash_log_label)
        
        opt_row += 1
        
        # RAM
        ttk.Label(options_frame, text="RAM (GB):").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        ttk.Entry(options_frame, textvariable=self.ram_gb, width=15).grid(row=opt_row, column=1, sticky=tk.W, pady=2)
        opt_row += 1
        
        # No DB update checkbox
        ttk.Checkbutton(options_frame, text="No database update (offline)", 
                       variable=self.no_db_update).grid(row=opt_row, column=0, columnspan=2, sticky=tk.W, pady=2)
        
        # Initialize CurseForge key visibility
        self.toggle_curseforge_key()
        
        row += 1
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=row, column=0, columnspan=2, pady=10)
        
        self.run_button = ttk.Button(buttons_frame, text="Run Analysis", command=self.run_analysis)
        self.run_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(buttons_frame, text="Stop", command=self.stop_analysis, state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        ttk.Button(buttons_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)
        
        row += 1
        
        # Status line
        status_frame = ttk.Frame(main_frame)
        status_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        status_frame.columnconfigure(1, weight=1)
        
        ttk.Label(status_frame, text="Status:").grid(row=0, column=0, sticky=tk.W)
        ttk.Label(status_frame, textvariable=self.status_text).grid(row=0, column=1, sticky=tk.W, padx=(5, 0))
        
        row += 1
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=2)
        
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
        
        # Handle analysis mode
        if self.analysis_mode.get() == "Deep":
            cmd.append("--online")
            
            if self.curseforge_enabled.get():
                cmd.append("--curseforge")
                if self.curseforge_key.get():
                    cmd.extend(["--curseforge-key", self.curseforge_key.get()])
        
        # Handle version/loader dropdowns
        mc_version = self.mc_version.get()
        if mc_version and mc_version != "Auto":
            cmd.extend(["--mc", mc_version])
        
        loader = self.loader.get()
        if loader and loader != "Auto":
            cmd.extend(["--loader", loader])
        
        if self.ram_gb.get():
            try:
                float(self.ram_gb.get())
                cmd.extend(["--ram-gb", self.ram_gb.get()])
            except ValueError:
                raise ValueError("RAM must be a valid number")
        
        if self.no_db_update.get():
            cmd.append("--no-db-update")
        
        # Add crash log if provided
        if self.crash_log_file.get():
            cmd.extend(["--crash-log", self.crash_log_file.get()])
        
        return cmd
    
    def run_analysis_thread(self):
        """Run the analysis in a separate thread"""
        try:
            self.root.after(0, lambda: self.update_status("Running"))
            
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
                self.root.after(0, lambda: self.update_status("Done"))
                
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
                self.root.after(0, lambda: self.update_status("Error"))
                
        except ValueError as e:
            self.log_message(f"ERROR: {e}")
            self.root.after(0, lambda: self.update_status("Error"))
        except Exception as e:
            self.log_message(f"ERROR: {e}")
            self.root.after(0, lambda: self.update_status("Error"))
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
        
        # Validate path
        path = self.normalize_path(self.mods_folder.get())
        if not path:
            messagebox.showerror("Error", "Invalid mods folder path")
            return
        
        self.mods_folder.set(str(path))
        
        # Disable UI
        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.progress.start()
        self.update_status("Starting...")
        
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
                self.update_status("Stopped")
            except Exception as e:
                self.log_message(f"Error stopping process: {e}")
        
        self.analysis_finished()
    
    def analysis_finished(self):
        """Re-enable UI after analysis"""
        self.run_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress.stop()
        self.process = None
        
        # Set final status if not already set
        if self.status_text.get() == "Running":
            self.update_status("Idle")
    
    def run(self):
        """Start the GUI"""
        self.root.mainloop()


def main():
    # Create and run the GUI
    app = ModpackDoctorGUI()
    app.run()


if __name__ == "__main__":
    main()