import sys
import threading
import tkinter as tk
import datetime
import schedule
import time
import json
import os
from tkinter import messagebox
from .console_output import ConsoleOutput
from .virus_total_checker import VirusTotalChecker
import datetime
from tkinter import filedialog
import matplotlib.pyplot as plt

class App:
    def __init__(self, master):
        self.master = master
        master.title('ThreatScraper')
        self.threat_checker = None  # Initialize the VirusTotalChecker object as None

        # Create API key entry
        self.api_key_label = tk.Label(master, text='API Key:')
        self.api_key_label.grid(row=0, column=0)
        self.api_key_entry = tk.Entry(master, width=50)
        self.api_key_entry.grid(row=0, column=1)

        # Create hash value entry
        self.hash_value_label = tk.Label(master, text='Hash Value:')
        self.hash_value_label.grid(row=1, column=0)
        self.hash_value_entry = tk.Entry(master, width=50)
        self.hash_value_entry.grid(row=1, column=1)
        
        # Create hash type selection
        self.hash_type = tk.StringVar(master)  # create a tkinter string variable
        self.hash_type.set("SHA-256")  # set default value
        self.hash_types = ["MD5", "SHA-1", "SHA-256"]  # list of hash types
        self.hash_type_option = tk.OptionMenu(master, self.hash_type, *self.hash_types)
        self.hash_type_option.grid(row=1, column=2)

        # Create filename entry
        self.filename_label = tk.Label(master, text='Excel File:')
        self.filename_label.grid(row=2, column=0)
        self.filename_entry = tk.Entry(master, width=50)
        self.filename_entry.grid(row=2, column=1)

        # Create time entry
        self.time_label = tk.Label(master, text='Schedule Times (HH:MM) Separated by comma:')
        self.time_label.grid(row=3, column=0)
        self.time_entry = tk.Entry(master, width=50)
        self.time_entry.grid(row=3, column=1)

        # Load saved configurations
        self.config_filename = 'config.json'
        self.load_config()

        # Checkbox for rescanning
        self.rescan_var = tk.BooleanVar()
        self.rescan_checkbox = tk.Checkbutton(master, text="Rescan hash", variable=self.rescan_var)
        self.rescan_checkbox.grid(row=2, column=2, columnspan=2)

        # Create check button
        self.check_button = tk.Button(master, text='Check VirusTotal', command=self.check_virustotal)
        self.check_button.grid(row=5, column=1)

        # Create start button
        self.start_button = tk.Button(master, text='Start Schedule', command=self.start_schedule)
        self.start_button.grid(row=5, column=2)

        # Create stop button
        self.stop_button = tk.Button(master, text='Stop Schedule', command=self.stop_schedule, state='disabled')
        self.stop_button.grid(row=6, column=2)

        # Create submit file button
        self.submit_file_button = tk.Button(master, text='Submit File for Analysis', command=self.submit_file)
        self.submit_file_button.grid(row=5, column=0)

        # Create console output in main window
        self.console_text = tk.Text(master, state='disabled', height=5)
        self.console_text.grid(row=7, column=0, columnspan=2, sticky='nsew')
        self.console_output = ConsoleOutput(self.console_text)
        self.console_output.set_text_widget_state('normal')
        sys.stdout = self.console_output

        # Configure the grid to make the console text box resize with the window
        master.grid_rowconfigure(7, weight=1)
        master.grid_columnconfigure(0, weight=1)
        master.grid_columnconfigure(1, weight=1)

        # Initialize schedule variables
        self.schedule_thread = None
        self.schedule_running = False

        # Start the graph
        self.threat_graph = None

    def load_config(self):
        # Check if config file exists
        if os.path.exists(self.config_filename):
            with open(self.config_filename, 'r') as f:
                config = json.load(f)
                
                # Load saved API key
                if 'api_key' in config:
                    self.api_key_entry.insert(0, config['api_key'])
                
                # Load saved hash value
                if 'hash_value' in config:
                    self.hash_value_entry.insert(0, config['hash_value'])

                # Load saved hash type
                if 'hash_type' in config:
                    self.hash_type.set(config['hash_type'])
                
                # Load saved filename
                if 'filename' in config:
                    self.filename_entry.insert(0, config['filename'])
                
                # Load saved schedule times
                if 'schedule_times' in config:
                    self.time_entry.insert(0, config['schedule_times'])

    def save_config(self):
        config = {
            'api_key': self.api_key_entry.get(),
            'hash_value': self.hash_value_entry.get(),
            'hash_type': self.hash_type.get(),
            'filename': self.filename_entry.get(),
            'schedule_times': self.time_entry.get(),
        }

        with open(self.config_filename, 'w') as f:
            json.dump(config, f, indent=4)

    def submit_file(self):
        file_path = filedialog.askopenfilename()
        if file_path:
            if self.threat_checker is None:
                api_key = self.api_key_entry.get()
                hash_value = self.hash_value_entry.get()
                hash_type = self.hash_type.get()
                filename = self.filename_entry.get()
                self.threat_checker = VirusTotalChecker(api_key, hash_value, hash_type, filename, self.console_output, self.master)

            self.threat_checker.submit_file(file_path)

    def check_virustotal(self):
        api_key = self.api_key_entry.get()
        hash_value = self.hash_value_entry.get()
        hash_type = self.hash_type.get()
        filename = self.filename_entry.get()

        # Check if the user has specified an API key
        if not api_key.strip():
            messagebox.showwarning(
                "API Key Required",
                "Please enter your VirusTotal API Key."
            )
            return

        # Check if the user has specified a hash value
        if not hash_value.strip():
            messagebox.showwarning(
                "Hash Value Required",
                "Please enter a Hash Value to check."
            )
            return

        # Check if filename is entered
        if not filename.strip():
            messagebox.showerror(
                "Filename Required",
                "Please enter the path to an Excel file.",
            )
            return

        if self.threat_checker is None:
            self.threat_checker = VirusTotalChecker(api_key, hash_value, hash_type, filename, self.console_output, self.master)
        
        if self.rescan_var.get():  # if checkbox is checked
            self.master.after(0, self.threat_checker.rescan_hash)
        else:
            self.master.after(0, self.threat_checker.check_virustotal)

        # Save configurations before running the check
        self.save_config()

        # Display the graphs
        plt.show(block=False)


    def start_schedule(self):
        # Get schedule times from entry
        schedule_times = self.time_entry.get().split(',')

        # Disable start button and enable stop button
        self.start_button.configure(state='disabled')
        self.stop_button.configure(state='normal')

        # Loop through schedule times and schedule checks
        for schedule_time in schedule_times:
            # Check if time is valid
            try:
                datetime.datetime.strptime(schedule_time.strip(), '%H:%M')
            except ValueError:
                messagebox.showerror('Invalid Time', f'{schedule_time} is not a valid time. Please enter a valid time in HH:MM format')
                return
            
            # Schedule daily check at this time
            schedule.every().day.at(schedule_time.strip()).do(self.master.after, 0, self.check_virustotal)

        # Save configurations before starting the schedule
        self.save_config()

        # Set schedule_running to True
        self.schedule_running = True

        # Update console window
        self.console_output.write('Schedule started\n')

        # Start schedule thread
        self.schedule_thread = threading.Thread(target=self.run_schedule, daemon=True)
        self.schedule_thread.start()

    def run_schedule(self):
        while self.schedule_running:
            schedule.run_pending()
            time.sleep(1)

        # Update console window
        self.console_output.write('Schedule stopped\n')

    def stop_schedule(self):
        # Enable start button and disable stop button
        self.start_button.configure(state='normal')
        self.stop_button.configure(state='disabled')

        # Clear schedule
        schedule.clear()

        # Set schedule_running to False
        self.schedule_running = False

    def quit(self):
        sys.stdout = sys.__stdout__
        self.master.destroy()

    def show_graph(self):
        self.threat_checker.start()
