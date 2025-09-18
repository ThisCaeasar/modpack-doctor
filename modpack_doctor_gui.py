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


class ModpackDoctorGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Modpack Doctor GUI")
        self.root.geometry("800x700")
        self.root.minsize(600, 500)
        
        # Variables
        self.mods_folder = tk.StringVar()
        self.online = tk.BooleanVar()
        self.curseforge = tk.BooleanVar()
        self.curseforge_key = tk.StringVar()
        self.mc_version = tk.StringVar()
        self.loader = tk.StringVar()
        self.ram_gb = tk.StringVar()
        self.no_db_update = tk.BooleanVar()
        
        # Process tracking
        self.process = None
        self.output_file = None
        
        self.create_widgets()
        
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
        
        ttk.Entry(folder_frame, textvariable=self.mods_folder).grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(folder_frame, text="Browse", command=self.browse_folder).grid(row=0, column=1)
        
        row += 1
        
        # Options frame
        options_frame = ttk.LabelFrame(main_frame, text="Options", padding="5")
        options_frame.grid(row=row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        options_frame.columnconfigure(1, weight=1)
        
        opt_row = 0
        
        # Online checkbox
        ttk.Checkbutton(options_frame, text="Online (Modrinth API)", 
                       variable=self.online).grid(row=opt_row, column=0, columnspan=2, sticky=tk.W, pady=2)
        opt_row += 1
        
        # CurseForge checkbox
        ttk.Checkbutton(options_frame, text="CurseForge API", 
                       variable=self.curseforge).grid(row=opt_row, column=0, columnspan=2, sticky=tk.W, pady=2)
        opt_row += 1
        
        # CurseForge key
        ttk.Label(options_frame, text="CurseForge API Key:").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        ttk.Entry(options_frame, textvariable=self.curseforge_key, show="*").grid(row=opt_row, column=1, sticky=(tk.W, tk.E), pady=2)
        opt_row += 1
        
        # MC Version
        ttk.Label(options_frame, text="Minecraft Version:").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        ttk.Entry(options_frame, textvariable=self.mc_version, width=15).grid(row=opt_row, column=1, sticky=tk.W, pady=2)
        opt_row += 1
        
        # Loader
        ttk.Label(options_frame, text="Loader:").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        loader_combo = ttk.Combobox(options_frame, textvariable=self.loader, width=15,
                                   values=["", "fabric", "forge", "quilt", "neoforge"], state="readonly")
        loader_combo.grid(row=opt_row, column=1, sticky=tk.W, pady=2)
        opt_row += 1
        
        # RAM
        ttk.Label(options_frame, text="RAM (GB):").grid(row=opt_row, column=0, sticky=tk.W, pady=2)
        ttk.Entry(options_frame, textvariable=self.ram_gb, width=15).grid(row=opt_row, column=1, sticky=tk.W, pady=2)
        opt_row += 1
        
        # No DB update checkbox
        ttk.Checkbutton(options_frame, text="No database update (offline)", 
                       variable=self.no_db_update).grid(row=opt_row, column=0, columnspan=2, sticky=tk.W, pady=2)
        
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