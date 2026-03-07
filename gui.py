import tkinter as tk

def run_extract():
    # Call your emv_extract.py logic here
    pass

def run_report():
    # Call your emv_report.py logic here
    pass

root = tk.Tk()
root.title("EMV Lab Toolkit")

 # Buttons to trigger extraction and report generation
btn_extract = tk.Button(root, text="Extract Card", command=run_extract)
btn_extract.pack(pady=5)

btn_report = tk.Button(root, text="Generate Report", command=run_report)
btn_report.pack(pady=5)

root.mainloop()
