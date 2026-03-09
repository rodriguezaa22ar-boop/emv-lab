import tkinter as tk
import subprocess
from tkinter import messagebox, scrolledtext

class EMVGUI:
    def __init__(self, root):
        self.root = root
        root.title("EMV Lab Console")
        root.geometry("700x500")

        frame = tk.Frame(root)
        frame.pack(pady=10)

        self.extract_btn = tk.Button(frame, text="Run EMV Extract", command=self.run_extract)
        self.extract_btn.pack(side=tk.LEFT, padx=10)

        self.report_btn = tk.Button(frame, text="Generate Report", command=self.run_report)
        self.report_btn.pack(side=tk.LEFT, padx=10)

        self.output = scrolledtext.ScrolledText(root, wrap=tk.WORD)
        self.output.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def run_command(self, command):
        self.output.insert(tk.END, f"\nRunning: {' '.join(command)}\n\n")
        self.output.see(tk.END)

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True
            )

            self.output.insert(tk.END, result.stdout)
            self.output.insert(tk.END, result.stderr)

        except Exception as e:
            messagebox.showerror("Error", str(e))

        self.output.see(tk.END)

    def run_extract(self):
        self.run_command(["python3", "emv_extract.py"])

    def run_report(self):
        self.run_command(["python3", "emv_report.py"])


if __name__ == "__main__":
    root = tk.Tk()
    app = EMVGUI(root)
    root.mainloop()
