import tkinter as tk

from src.app import App

if __name__ == "__main__":
    # Create root window
    root = tk.Tk()
    root.iconbitmap('ThreatScraper.ico')
    # Create app instance
    app = App(root)

    # Run the application
    root.mainloop()
