import tkinter as tk
from tkinter import ttk
import threading
import time
import os

from capture.packet_capture import start_capture, packet_queue
from honeypot.cowrie_manager import start_honeypot, stop_honeypot
from firewall.ufw_manager import get_ufw_rules, enable_ufw, disable_ufw
from firewall.iptables_manager import get_iptables_rules
from logs.sni_logs import load_logs
from ids.flow_ids import flow_queue,start_flow_ids
from ransomware.detector import scan_file
from tkinter import filedialog
from dpi.dpi_engine import start_dpi, dpi_queue
from xai.xai_engine import xai_queue

COWRIE_LOG = "/home/cowrie/cowrie/var/log/cowrie/cowrie.log"



# ---------------- Packet Capture Tab ----------------

class PacketTab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        self.tree=ttk.Treeview(
            self,
            columns=("src","dst","proto","port","len"),
            show="headings"
        )

        for c in ("src","dst","proto","port","len"):

            self.tree.heading(c,text=c.upper())
            self.tree.column(c,width=140)

        self.tree.pack(fill="both",expand=True)

        ttk.Button(
            self,
            text="Start Capture",
            command=self.start
        ).pack()

        self.update()


    def start(self):

        threading.Thread(
            target=start_capture,
            daemon=True
        ).start()


    def update(self):

        while not packet_queue.empty():

            self.tree.insert(
                "",
                "end",
                values=packet_queue.get()
            )

            if len(self.tree.get_children()) > 500:
                self.tree.delete(self.tree.get_children()[0])

        self.after(300,self.update)


# ---------------- Honeypot Tab ----------------

class HoneypotTab(ttk.Frame):

    def __init__(self, parent):

        super().__init__(parent)

        # ---------- TITLE ----------
        title = ttk.Label(
            self,
            text="SSH Honeypot Monitor",
            font=("Arial", 16, "bold")
        )
        title.pack(pady=10)

        # ---------- BUTTON FRAME ----------
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        self.start_btn = ttk.Button(
            btn_frame,
            text="Start Honeypot",
            command=self.start_hp
        )
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(
            btn_frame,
            text="Stop Honeypot",
            command=self.stop_hp
        )
        self.stop_btn.pack(side="left", padx=5)

        # ---------- STATUS ----------
        self.status = ttk.Label(
            self,
            text="Status: Stopped",
            foreground="red",
            font=("Arial", 10, "bold")
        )
        self.status.pack(pady=5)

        # ---------- LOG WINDOW ----------
        self.log_box = tk.Text(
            self,
            bg="#111",
            fg="#00FF00",
            font=("Consolas", 11),
            height=25
        )

        self.log_box.pack(fill="both", expand=True, padx=10, pady=10)

        self.running = False


    # ---------- START HONEYPOT ----------
    def start_hp(self):

        start_honeypot()

        if not self.running:

            self.running = True
            self.status.config(text="Status: Running", foreground="green")

            threading.Thread(
                target=self.stream_logs,
                daemon=True
            ).start()


    # ---------- STOP HONEYPOT ----------
    def stop_hp(self):

        stop_honeypot()

        self.running = False
        self.status.config(text="Status: Stopped", foreground="red")


    # ---------- STREAM LOGS ----------
    def stream_logs(self):

        import re

        attacker_ip = ""

        try:
            with open(COWRIE_LOG, "r") as f:

                f.seek(0, os.SEEK_END)

                while self.running:

                    line = f.readline()

                    if not line:
                        time.sleep(0.5)
                        continue


                    # ---------- ATTACKER CONNECTION ----------
                    if "New connection" in line:

                        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)

                        if ip_match:
                            attacker_ip = ip_match.group(1)
                            msg = f"⚠ Attacker connected from {attacker_ip}"

                            self.log_box.insert("end", msg + "\n")
                            self.log_box.see("end")


                    # ---------- LOGIN ATTEMPT ----------
                    elif "login attempt" in line:

                        cred_match = re.search(
                            r"login attempt \[b'(.*?)'/b'(.*?)'\]",
                            line
                        )

                        if cred_match:

                            username = cred_match.group(1)
                            password = cred_match.group(2)

                            msg1 = f"👤 Username tried: {username}"
                            msg2 = f"🔑 Password tried: {password}"

                            self.log_box.insert("end", msg1 + "\n")
                            self.log_box.insert("end", msg2 + "\n")
                            self.log_box.see("end")


                    # ---------- LOGIN FAILURE ----------
                    elif "failed auth" in line:

                        msg = "❌ Authentication failed"

                        self.log_box.insert("end", msg + "\n")
                        self.log_box.see("end")


                    # ---------- LOGIN SUCCESS ----------
                    elif "login succeeded" in line:

                        msg = "✅ Attacker logged in successfully"

                        self.log_box.insert("end", msg + "\n")
                        self.log_box.see("end")


                    # ---------- COMMAND EXECUTION ----------
                    elif "command input" in line:

                        cmd_match = re.search(
                            r"command input: (.*)",
                            line
                        )

                        if cmd_match:

                            cmd = cmd_match.group(1)

                            msg = f"💻 Command executed: {cmd}"

                            self.log_box.insert("end", msg + "\n")
                            self.log_box.see("end")


        except Exception as e:

            self.log_box.insert("end", f"[ERROR] {e}\n")
# ---------------- UFW Tab ----------------

class UFWTab(ttk.Frame):

    def __init__(self, parent):

        super().__init__(parent)

        title = ttk.Label(
            self,
            text="UFW Firewall Rules",
            font=("Arial",16,"bold")
        )
        title.pack(pady=10)

        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        ttk.Button(
            btn_frame,
            text="Refresh",
            command=self.refresh
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Enable Firewall",
            command=enable_ufw
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Disable Firewall",
            command=disable_ufw
        ).pack(side="left", padx=5)

        table_frame = ttk.Frame(self)
        table_frame.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(table_frame)

        self.tree = ttk.Treeview(
            table_frame,
            columns=("rule","action","port","proto","source"),
            show="headings",
            yscrollcommand=scrollbar.set
        )

        self.tree.heading("rule", text="Rule")
        self.tree.heading("action", text="Action")
        self.tree.heading("port", text="Port")
        self.tree.heading("proto", text="Protocol")
        self.tree.heading("source", text="Source")

        self.tree.column("rule", width=60)
        self.tree.column("action", width=100)
        self.tree.column("port", width=100)
        self.tree.column("proto", width=100)
        self.tree.column("source", width=200)

        scrollbar.config(command=self.tree.yview)

        scrollbar.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)

        self.status = ttk.Label(self,text="")
        self.status.pack(pady=5)

        self.refresh()


    def refresh(self):

        for row in self.tree.get_children():
            self.tree.delete(row)

        rules = get_ufw_rules()

        for r in rules:
            self.tree.insert("", "end", values=r)

        self.status.config(text=f"{len(rules)} firewall rules loaded")
# ---------------- IPTables Tab ----------------

class IPTablesTab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        self.tree=ttk.Treeview(self,columns=("rule"),show="headings")
        self.tree.heading("rule",text="IPTABLES RULES")
        self.tree.pack(fill="both",expand=True)

        ttk.Button(self,text="Refresh",command=self.refresh).pack()

        self.refresh()


    def refresh(self):

        for i in self.tree.get_children():
            self.tree.delete(i)

        for r in get_iptables_rules():

            self.tree.insert("", "end", values=(r,))


# ---------------- SNI Log Tab ----------------

class SNILogTab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        self.tree=ttk.Treeview(
            self,
            columns=("time","client","sni","server","result"),
            show="headings"
        )

        for c in ("time","client","sni","server","result"):
            self.tree.heading(c,text=c.upper())

        self.tree.pack(fill="both",expand=True)

        ttk.Button(self,text="Refresh",command=self.refresh).pack()

        self.refresh()


    def refresh(self):

        for i in self.tree.get_children():
            self.tree.delete(i)

        for r in load_logs():

            self.tree.insert("", "end", values=r)


# ---------------- Flow IDS Tab ----------------

class FlowIDSTab(ttk.Frame):

    def __init__(self, parent):

        super().__init__(parent)

        self.tree = ttk.Treeview(
            self,
            columns=("src","dst","proto","len","result","conf"),
            show="headings"
        )

        for c in ("src","dst","proto","len","result","conf"):
            self.tree.heading(c, text=c.upper())

        self.tree.pack(fill="both", expand=True)

        self.update()


    def update(self):

        while not flow_queue.empty():

            self.tree.insert(
                "",
                "end",
                values=flow_queue.get()
            )

            if len(self.tree.get_children()) > 500:
                self.tree.delete(self.tree.get_children()[0])

        self.after(300, self.update)

# ---------------- Ransomware Detector Tab ----------------

class RansomwareTab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        ttk.Label(
            self,
            text="Ransomware File Scanner",
            font=("Arial",14)
        ).pack(pady=10)

        ttk.Button(
            self,
            text="Select File to Scan",
            command=self.scan
        ).pack(pady=10)

        self.result = tk.Label(
            self,
            text="",
            font=("Arial",12)
        )

        self.result.pack(pady=20)


    def scan(self):

        file_path = filedialog.askopenfilename()

        if file_path:

            result = scan_file(file_path)

            self.result.config(text=result)

# ---------------- DPI Tab ----------------#

class DPITab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        self.tree = ttk.Treeview(
            self,
            columns=("src","dst","proto","len","result","conf"),
            show="headings"
        )

        for c in ("src","dst","proto","len","result","conf"):
            self.tree.heading(c,text=c.upper())

        self.tree.pack(fill="both",expand=True)

        ttk.Button(
            self,
            text="Start DPI Engine",
            command=self.start
        ).pack()

        self.update()


    def start(self):

        threading.Thread(
            target=start_dpi,
            daemon=True
        ).start()


    def update(self):

        while not dpi_queue.empty():

            self.tree.insert("", "end",
                             values=dpi_queue.get())

        self.after(300,self.update)
# ----------------XAI TAB----------------#

class XAITab(ttk.Frame):

    def __init__(self, parent):

        super().__init__(parent)

        self.tree = ttk.Treeview(
            self,
            columns=("src","dst","attack","explanation"),
            show="headings"
        )

        self.tree.heading("src", text="SOURCE")
        self.tree.heading("dst", text="DESTINATION")
        self.tree.heading("attack", text="ATTACK TYPE")
        self.tree.heading("explanation", text="AI EXPLANATION")

        self.tree.column("src", width=140)
        self.tree.column("dst", width=140)
        self.tree.column("attack", width=150)
        self.tree.column("explanation", width=500)

        self.tree.pack(fill="both", expand=True)

        self.update()


    def update(self):

        while not xai_queue.empty():

            self.tree.insert(
                "",
                "end",
                values=xai_queue.get()
            )

        self.after(300, self.update)
# ---------------- MAIN GUI ----------------

def main():

    root=tk.Tk()
    start_flow_ids()

    root.title("QUOR DEFENDER")

    root.geometry("1000x600")

    notebook=ttk.Notebook(root)
    notebook.pack(fill="both",expand=True)

    notebook.add(HoneypotTab(notebook),text="Honeypot")
    notebook.add(UFWTab(notebook),text="UFW")
    notebook.add(IPTablesTab(notebook),text="iptables")
    notebook.add(PacketTab(notebook),text="Live Capture")
    notebook.add(SNILogTab(notebook),text="SNI Logs")
    notebook.add(FlowIDSTab(notebook),text="Flow IDS")
    notebook.add(RansomwareTab(notebook),text="Ransomware Detector")
    notebook.add(DPITab(notebook), text="DPI Engine")
    notebook.add(XAITab(notebook), text="XAI")
    root.mainloop()


if __name__=="__main__":
    main()