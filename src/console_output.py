import tkinter as tk


class ConsoleOutput:
    def __init__(self, text_widget):
        self.text_widget = text_widget

    def write(self, string):
        self.text_widget.insert(tk.END, string)
        self.text_widget.see(tk.END)

    def flush(self):
        pass

    def set_text_widget_state(self, state):
        self.text_widget.configure(state=state)
