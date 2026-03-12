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
LOG_FILE ="/home/quor/Desktop/firewall/DEFENDER/venv/logs/sni_spoof_log.csv"
  





def create_table(parent, columns):

    frame = ttk.Frame(parent)
    frame.pack(fill="both", expand=True, padx=10, pady=10)

    scrollbar = ttk.Scrollbar(frame)

    tree = ttk.Treeview(
        frame,
        columns=columns,
        show="headings",
        yscrollcommand=scrollbar.set
    )

    for c in columns:
        tree.heading(c, text=c.upper())
        tree.column(c, width=150)

    scrollbar.config(command=tree.yview)

    scrollbar.pack(side="right", fill="y")
    tree.pack(fill="both", expand=True)

    return tree
#--------------------------------Dashboard--------------------------------------------------------------------

class DashboardTab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        ttk.Label(
            self,
            text="QUOR DEFENDER — Security Dashboard",
            font=("Arial",18,"bold")
        ).pack(pady=20)

        container = ttk.Frame(self)
        container.pack()

        self.packet_count = self.card(container,"Packets Captured","0")
        self.ids_count = self.card(container,"IDS Alerts","0")
        self.blocked_count = self.card(container,"Blocked IPs","0")
        self.ai_count = self.card(container,"AI Detections","0")

        self.update_stats()


    def card(self,parent,title,value):

        frame = ttk.Frame(parent, padding=20)

        frame.pack(side="left", padx=20)

        ttk.Label(
            frame,
            text=title,
            font=("Arial",12,"bold")
        ).pack()

        label = ttk.Label(
            frame,
            text=value,
            font=("Arial",22)
        )

        label.pack()

        return label


    def update_stats(self):

        packets = len(packet_queue.queue)
        ids = len(flow_queue.queue)
        dpi = len(dpi_queue.queue)
        xai = len(xai_queue.queue)

        self.packet_count.config(text=str(packets))
        self.ids_count.config(text=str(ids))
        self.ai_count.config(text=str(xai))

        self.after(1000,self.update_stats)




# ---------------- Packet Capture Tab -------------------------------------------------------------------------------------------

class PacketTab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        ttk.Label(
            self,
            text="Live Packet Capture",
            font=("Arial",15,"bold")
        ).pack(pady=10)

        # -------- BUTTON BAR --------
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        self.start_btn = ttk.Button(
            btn_frame,
            text="Start Capture",
            command=self.start
        )
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = ttk.Button(
            btn_frame,
            text="Stop Capture",
            command=self.stop
        )
        self.stop_btn.pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Clear Table",
            command=self.clear_table
        ).pack(side="left", padx=5)

        # -------- STATUS --------
        self.status = ttk.Label(self,text="Status: Stopped")
        self.status.pack(pady=5)

        # -------- TABLE --------
        self.tree = create_table(self,("src","dst","proto","port","len"))

        # -------- CONTROL FLAG --------
        self.running = False

        self.update()


    # -------- START CAPTURE --------
    def start(self):

        if not self.running:

            self.running = True

            self.status.config(text="Status: Capturing")

            threading.Thread(
                target=start_capture,
                daemon=True
            ).start()


    # -------- STOP CAPTURE --------
    def stop(self):

        self.running = False

        self.status.config(text="Status: Stopped")


    # -------- CLEAR TABLE --------
    def clear_table(self):

        for row in self.tree.get_children():
            self.tree.delete(row)


    # -------- UPDATE TABLE --------
    def update(self):

        if self.running:

            while not packet_queue.empty():

                self.tree.insert(
                    "",
                    "end",
                    values=packet_queue.get()
                )

                if len(self.tree.get_children()) > 500:
                    self.tree.delete(self.tree.get_children()[0])

        self.after(300,self.update)









# ---------------- Honeypot Tab ----------------------------------------------------------------------------------------------------------

class HoneypotTab(ttk.Frame):

    def __init__(self, parent):

        super().__init__(parent)

        self.running = False

        # -------- HEADER --------
        ttk.Label(
            self,
            text="SSH Honeypot Monitor",
            font=("Arial",16,"bold")
        ).pack(pady=10)

        # -------- BUTTON BAR --------
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        ttk.Button(
            btn_frame,
            text="Start Honeypot",
            command=self.start_hp
        ).pack(side="left", padx=10)

        ttk.Button(
            btn_frame,
            text="Stop Honeypot",
            command=self.stop_hp
        ).pack(side="left", padx=10)

        ttk.Button(
            btn_frame,
            text="Clear Logs",
            command=self.clear_logs
        ).pack(side="left", padx=10)

        # -------- STATUS --------
        self.status = ttk.Label(
            self,
            text="Status: Stopped",
            font=("Arial",11)
        )
        self.status.pack(pady=5)

        # -------- LOG FRAME --------
        log_frame = ttk.Frame(self)
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        scrollbar = ttk.Scrollbar(log_frame)

        self.log = tk.Text(
            log_frame,
            bg="white",
            fg="black",
            font=("Consolas",11),
            yscrollcommand=scrollbar.set,
            relief="solid",
            bd=1
        )

        scrollbar.config(command=self.log.yview)

        scrollbar.pack(side="right", fill="y")
        self.log.pack(fill="both", expand=True)

        # -------- TAG COLORS --------
        self.log.tag_config("attacker", foreground="red")
        self.log.tag_config("login", foreground="blue")
        self.log.tag_config("command", foreground="green")
        self.log.tag_config("success", foreground="darkgreen")


    # -------- START HONEYPOT --------
    def start_hp(self):

        start_honeypot()

        if not self.running:

            self.running = True
            self.status.config(text="Status: Running")

            threading.Thread(
                target=self.stream_logs,
                daemon=True
            ).start()


    # -------- STOP HONEYPOT --------
    def stop_hp(self):

        stop_honeypot()

        self.running = False
        self.status.config(text="Status: Stopped")


    # -------- CLEAR GUI LOG --------
    def clear_logs(self):

        self.log.delete("1.0", tk.END)


    # -------- SAFE LOG INSERT --------
    def insert_log(self, message, tag):

        self.log.insert("end", message, tag)
        self.log.see("end")


    # -------- STREAM COWRIE LOGS --------
    def stream_logs(self):

        import re

        try:

            with open(COWRIE_LOG, "r") as f:

                f.seek(0, os.SEEK_END)

                while self.running:

                    line = f.readline()

                    if not line:
                        time.sleep(0.5)
                        continue

                    # -------- TIMESTAMP --------
                    ts = re.search(r'^(\d{4}-\d{2}-\d{2}T[\d:\.]+Z)', line)

                    timestamp = ts.group(1) if ts else "TIME"

                    # -------- ATTACKER CONNECT --------
                    if "New connection" in line:

                        ip = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)

                        if ip:

                            msg = f"[{timestamp}] ATTACKER CONNECTED → {ip.group(1)}\n"

                            self.after(0, self.insert_log, msg, "attacker")


                    # -------- LOGIN ATTEMPT --------
                    elif "login attempt" in line:

                        cred = re.search(
                            r"login attempt \[b'(.*?)'/b'(.*?)'\]",
                            line
                        )

                        if cred:

                            user = cred.group(1)
                            pwd = cred.group(2)

                            msg = f"[{timestamp}] LOGIN ATTEMPT → {user} / {pwd}\n"

                            self.after(0, self.insert_log, msg, "login")


                    # -------- LOGIN SUCCESS --------
                    elif "login succeeded" in line:

                        msg = f"[{timestamp}] LOGIN SUCCESS\n"

                        self.after(0, self.insert_log, msg, "success")


                    # -------- COMMAND EXECUTION --------
                    elif "command input" in line:

                        cmd = re.search(
                            r"command input: (.*)",
                            line
                        )

                        if cmd:

                            msg = f"[{timestamp}] COMMAND → {cmd.group(1)}\n"

                            self.after(0, self.insert_log, msg, "command")


        except Exception as e:

            self.after(
                0,
                self.insert_log,
                f"[ERROR] {e}\n",
                "attacker"
            )








# ---------------- UFW Tab -----------------------------------------------------------------------------------------------------------------

class UFWTab(ttk.Frame):

    def __init__(self,parent):

        super().__init__(parent)

        ttk.Label(
            self,
            text="Firewall — System Settings",
            font=("Arial",16,"bold")
        ).pack(pady=10)

        # -------- BUTTON BAR --------
        btn = ttk.Frame(self)
        btn.pack(pady=5)

        ttk.Button(
            btn,
            text="Refresh",
            command=self.refresh
        ).pack(side="left", padx=5)

        ttk.Button(
            btn,
            text="Enable",
            command=enable_ufw
        ).pack(side="left", padx=5)

        ttk.Button(
            btn,
            text="Disable",
            command=disable_ufw
        ).pack(side="left", padx=5)

        ttk.Button(
            btn,
            text="Add Rule",
            command=self.add_rule_window
        ).pack(side="left", padx=5)

        ttk.Button(
            btn,
            text="Delete Rule",
            command=self.delete_rule
        ).pack(side="left", padx=5)

        ttk.Button(
            btn,
            text="Reload",
            command=self.reload_firewall
        ).pack(side="left", padx=5)

        # -------- RULE TABLE --------
        self.tree = create_table(
            self,
            ("rule","action","port","proto","source")
        )

        # -------- STATUS BAR --------
        self.status = ttk.Label(self,text="")
        self.status.pack(pady=5)

        self.refresh()


    # -------- REFRESH RULES --------
    def refresh(self):

        for row in self.tree.get_children():
            self.tree.delete(row)

        rules = get_ufw_rules()

        for i,r in enumerate(rules):

            tag = "even" if i % 2 == 0 else "odd"

            self.tree.insert("", "end", values=r, tags=(tag,))

        self.status.config(text=f"{len(rules)} rules loaded")


    # -------- ADD RULE WINDOW --------
    def add_rule_window(self):

        win = tk.Toplevel(self)
        win.title("Add Firewall Rule")
        win.geometry("300x220")

        ttk.Label(win,text="Action").pack()
        action = ttk.Combobox(win,values=["allow","deny"])
        action.pack()

        ttk.Label(win,text="Port").pack()
        port = ttk.Entry(win)
        port.pack()

        ttk.Label(win,text="Protocol").pack()
        proto = ttk.Combobox(win,values=["tcp","udp"])
        proto.pack()

        def add_rule():

            import subprocess

            a = action.get()
            p = port.get()
            pr = proto.get()

            cmd = ["sudo","ufw",a,f"{p}/{pr}"]

            subprocess.run(cmd)

            win.destroy()
            self.refresh()

        ttk.Button(
            win,
            text="Add Rule",
            command=add_rule
        ).pack(pady=10)


    # -------- DELETE RULE --------
    def delete_rule(self):

        import subprocess

        selected = self.tree.selection()

        if not selected:
            return

        item = self.tree.item(selected[0])
        rule_number = item["values"][0]

        subprocess.run(
            ["sudo","ufw","--force","delete",str(rule_number)]
        )

        self.refresh()


    # -------- RELOAD FIREWALL --------
    def reload_firewall(self):

        import subprocess

        subprocess.run(["sudo","ufw","reload"])

        self.refresh()








# ---------------- IPTables Tab -------------------------------------------------------------------------------------------

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










# ---------------- SNI Log Tab ----------------------------------------------------------------------------

class SNILogTab(ttk.Frame):

    def __init__(self, parent):

        super().__init__(parent)

        from logs.sni_logs import LOG_FILE, load_logs, clear_logs

        self.LOG_FILE = LOG_FILE
        self.load_logs = load_logs
        self.clear_logs_file = clear_logs

        self.auto_refresh = True

        ttk.Label(
            self,
            text="TLS SNI Logs",
            font=("Arial", 15, "bold")
        ).pack(pady=10)

        # BUTTON BAR
        btn_frame = ttk.Frame(self)
        btn_frame.pack(pady=5)

        ttk.Button(
            btn_frame,
            text="Refresh",
            command=self.refresh
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Clear Table",
            command=self.clear_table
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Clear Log File",
            command=self.clear_log_file
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Export CSV",
            command=self.export_logs
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Toggle Auto Refresh",
            command=self.toggle_refresh
        ).pack(side="left", padx=5)

        # TABLE
        self.tree = create_table(
            self,
            ("time", "client", "sni", "server", "result")
        )

        # ROW COLORS
        self.tree.tag_configure("spoof", foreground="red", font=("Arial",10,"bold"))
        self.tree.tag_configure("malicious", foreground="orange")
        self.tree.tag_configure("normal", foreground="black")

        self.status = ttk.Label(self, text="")
        self.status.pack(pady=5)

        self.refresh()
        self.auto_update()

    # AUTO REFRESH
    def auto_update(self):

        if self.auto_refresh:
            self.refresh()

        self.after(2000, self.auto_update)

    def toggle_refresh(self):

        self.auto_refresh = not self.auto_refresh

        state = "ON" if self.auto_refresh else "OFF"

        self.status.config(text=f"Auto refresh {state}")

    # REFRESH
    def refresh(self):

        for i in self.tree.get_children():
            self.tree.delete(i)

        logs = self.load_logs()

        for r in logs:

            domain = str(r[2]).lower()
            result = str(r[4]).lower()

            if "spoof" in result:
                tag = "spoof"

            elif ".ru" in domain or "phish" in domain or "malware" in domain:
                tag = "malicious"

            else:
                tag = "normal"

            self.tree.insert(
                "",
                "end",
                values=r,
                tags=(tag,)
            )

        self.status.config(text=f"{len(logs)} log entries loaded")

    # CLEAR TABLE
    def clear_table(self):

        for row in self.tree.get_children():
            self.tree.delete(row)

        self.status.config(text="Table cleared")

    # CLEAR LOG FILE
    def clear_log_file(self):

        from tkinter import messagebox

        confirm = messagebox.askyesno(
            "Confirm",
            "Delete all SNI logs?"
        )

        if not confirm:
            return

        if self.clear_logs_file():

            self.clear_table()
            self.status.config(text="Log file cleared")

        else:

            self.status.config(text="Error clearing log file")

    # EXPORT LOGS
    def export_logs(self):

        from tkinter import filedialog
        import shutil

        path = filedialog.asksaveasfilename(
            defaultextension=".csv"
        )

        if not path:
            return

        shutil.copy(self.LOG_FILE, path)

        self.status.config(text="Logs exported")








# ---------------- Flow IDS Tab ----------------------------------------------------------------------------------------------------------

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









# ---------------- Ransomware Detector Tab ----------------------------------------------------------------------------------------------------------

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









# ---------------- DPI Tab -------------------------------------------------------------------------------------------

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







# ----------------XAI TAB-------------------------------------------------------------------------------------------

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










# ---------------- MAIN GUI ----------------------------------------------------------------------------------------------------------

def main():

    root=tk.Tk()
    start_flow_ids()

    root.title("QUOR DEFENDER")

    root.geometry("1000x600")

    notebook=ttk.Notebook(root)
    notebook.pack(fill="both",expand=True)

    notebook.add(DashboardTab(notebook),text="Dashboard")
    notebook.add(UFWTab(notebook),text="UFW")
    notebook.add(IPTablesTab(notebook),text="iptables")
    notebook.add(HoneypotTab(notebook),text="Honeypot")
    notebook.add(PacketTab(notebook),text="Live Capture")
    notebook.add(FlowIDSTab(notebook),text="Flow IDS")
    notebook.add(SNILogTab(notebook),text="SNI Logs")
    notebook.add(RansomwareTab(notebook),text="Ransomware Detector")
    notebook.add(DPITab(notebook), text="DPI Engine")
    notebook.add(XAITab(notebook), text="XAI")
    root.mainloop()


if __name__=="__main__":
    main()