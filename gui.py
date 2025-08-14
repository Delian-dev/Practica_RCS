import tkinter as tk
from tkinter import filedialog, scrolledtext
import subprocess
import os
import signal
import threading

def start_gui():
    file_path = {"selected": None}
    capture_proc = {"proc": None}
    is_running = {"value": True}
    folder_mode = {"enabled": False} #for the option of choosing a whole folder

    def open_main_window():
        #rebuilds the main window
        root = tk.Tk()
        root.title("Packet Analyzer")
        root.geometry("400x250")

        def choose_file(): #opens a menu that allows to choose a file for analysis
            path = filedialog.askopenfilename(
                title="Choose a capture file",
                filetypes=[("PCAP files", "*.pcap *.pcapng"), ("All files", "*.*")]
            )
            if path:
                file_path["selected"] = path
                folder_mode["enabled"] = False
                root.destroy()

        def choose_folder():
            path = filedialog.askdirectory(
                title = "Choose a folder with capture files (.pcap)"
            )
            if path:
                file_path["selected"] = path
                folder_mode["enabled"] = True
                root.destroy()

        def launch_capture_window(): #activates the window for live capture
            root.destroy()
            open_capture_window()

        tk.Label(root, text="Select capture method:", font=("Arial", 12)).pack(pady=10)
        tk.Button(root, text="📂 Choose Capture File", command=choose_file, width=30).pack(pady=5)
        tk.Button(root, text="📁 Choose Folder of Captures", command=choose_folder, width=30).pack(pady=5)
        tk.Button(root, text="🟢 Run Live Capture Script", command=launch_capture_window, width=30).pack(pady=5)

        root.mainloop()

    def open_capture_window(): #live capture window (shows the filters + a stop button)
        capture_window = tk.Tk()
        capture_window.title("Capturing Packets...")
        capture_window.geometry("700x500")

        text_output = scrolledtext.ScrolledText(capture_window, state='disabled', wrap='word')
        text_output.pack(expand=True, fill='both', padx=10, pady=10)

        def append_text(line): #this is basically in order to show the user the execution of the script (as if it would be executed directly in the cli)
            text_output.configure(state='normal')
            text_output.insert(tk.END, line + '\n')
            text_output.see(tk.END)
            text_output.configure(state='disabled')

        def stop_capture(): #triggered by the stop capture button
            is_running["value"] = False
            proc = capture_proc["proc"]
            if proc and proc.poll() is None:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT) #kills the shell process
                proc.wait()
            append_text("✅ Capture stopped.")
            capture_window.after(500, lambda: (
                capture_window.destroy(),
                open_main_window() #go back to the main window
            ))


        def run_script():
            try:
                proc = subprocess.Popen( #builds the process
                    ["bash", "start_capture.sh"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    preexec_fn=os.setsid
                )
                capture_proc["proc"] = proc
                file_path["selected"] = "capture.pcap" #after the script is interrupted, it will be immeditately analysed

                #background thread to read stdout
                def read_output():
                    try:
                        for line in proc.stdout:
                            if not is_running["value"]:
                                break
                            line = line.strip()
                            capture_window.after(0, append_text, line)
                    except Exception as e:
                        capture_window.after(0, append_text, f"Reader error: {e}")

                threading.Thread(target=read_output, daemon=True).start()

            except Exception as e:
                append_text(f"Error starting capture: {e}")

        tk.Button(capture_window, text="🛑 Stop Capture", command=stop_capture, width=30).pack(pady=5) #stop btn

        run_script()
        capture_window.mainloop()

    open_main_window()
    return file_path["selected"], folder_mode["enabled"] #returns the selected file or the file obtained from the live capture
