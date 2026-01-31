import psutil
import socket
import time
import csv
import os
import tkinter as tk
from tkinter import scrolledtext, ttk
import threading
import unicodedata

class CompactZenWatcher:
    def __init__(self, white_path="whitelist.csv", black_path="blacklist.csv"):
        self.white_path, self.black_path = white_path, black_path
        self.load_configs()
        
        self.root = tk.Tk()
        self.root.title("インフラGメン")
        self.root.geometry("1250x650") # 幅をほどよく固定
        
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both')

        font_config = ("MS Gothic", 10)
        self.alert_tab = scrolledtext.ScrolledText(self.notebook, bg="#1a0000", fg="#ff4444", font=font_config)
        self.normal_tab = scrolledtext.ScrolledText(self.notebook, bg="#001a00", fg="#44ff44", font=font_config)
        
        self.notebook.add(self.alert_tab, text=" 🚨 警告/未確認 ")
        self.notebook.add(self.normal_tab, text=" 🌐 通常/安全 ")

        self.normal_tab.tag_config('unregistered', background='#001a44')
        self.alert_tab.tag_config('blacklist', background='#440000', foreground='#ffffff')

        self.active_connections, self.dns_cache = {}, {}

    def get_display_width(self, text):
        return sum(2 if unicodedata.east_asian_width(c) in 'FWA' else 1 for c in text)

    def zen_slice_and_fill(self, text, width):
        """指定の幅に合わせて切り詰め＆パディング"""
        curr_w = 0
        sliced_text = ""
        for char in text:
            char_w = 2 if unicodedata.east_asian_width(char) in 'FWA' else 1
            if curr_w + char_w > width - 1: # 幅を超えるなら終了
                sliced_text += " " # 余白調整
                curr_w += 1
                break
            sliced_text += char
            curr_w += char_w
        return sliced_text + (' ' * (width - curr_w))

    def _read_csv(self, path):
        data = {"keywords": {}, "ports": {}, "ips": {}}
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8-sig') as f:
                    for row in csv.DictReader(f):
                        p, t, c = row['pattern'], row['type'], row['comment']
                        if t == 'keyword': data["keywords"][p.lower()] = c
                        elif t == 'port': data["ports"][int(p)] = c
                        elif t == 'ip': data["ips"][p] = c
            except: pass
        return data

    def load_configs(self):
        self.white_config = self._read_csv(self.white_path)
        self.black_config = self._read_csv(self.black_path)

    def log_to_tab(self, tab, message, tag=None):
        tab.insert(tk.END, f"[{time.strftime('%H:%M:%S')}] {message}\n", tag)
        tab.see(tk.END)

    def monitor(self):
        while True:
            self.load_configs()
            current_found = set()
            try: conns = psutil.net_connections(kind='inet')
            except: time.sleep(1); continue

            for conn in conns:
                if conn.status == 'ESTABLISHED' and getattr(conn, 'raddr', None):
                    rid, rp, pid = conn.raddr.ip, conn.raddr.port, conn.pid
                    cid = (rid, rp, pid)
                    current_found.add(cid)
                    if cid in self.active_connections: continue
                    
                    try: p_name = psutil.Process(pid).name()
                    except: p_name = "Unknown"
                    
                    try: host = socket.gethostbyaddr(rid)[0]
                    except: host = "Unknown-Host"
                    
                    label, reason, is_black, is_white = "", "", False, False

                    # 判定ロジック
                    if rid in self.black_config["ips"]: label, reason, is_black = self.black_config["ips"][rid], "BL-IP", True
                    elif rp in self.black_config["ports"]: label, reason, is_black = self.black_config["ports"][rp], "BL-Port", True
                    elif any(k in host.lower() for k in self.black_config["keywords"]):
                        for k, v in self.black_config["keywords"].items():
                            if k in host.lower(): label, reason, is_black = v, "BL-Key", True; break
                    
                    if not is_black:
                        if rid in self.white_config["ips"]: label, reason, is_white = self.white_config["ips"][rid], "WL-IP", True
                        elif any(k in host.lower() for k in self.white_config["keywords"]):
                            for k, v in self.white_config["keywords"].items():
                                if k in host.lower(): label, reason, is_white = v, "WL-Key", True; break
                        elif rp in self.white_config["ports"] and rp != 443:
                            label, reason, is_white = self.white_config["ports"][rp], "WL-Port", True

                    # --- 整列のコア：ZENパディング（幅を厳格に固定） ---
                    # 1. 理由ラベル (例: ??WEB??, WL-Key) - 12文字
                    prefix = "??WEB??     " if (not is_black and not is_white and rp == 443) else self.zen_slice_and_fill(f"({reason})", 12)
                    
                    # 2. プロセス名 - 18文字
                    f_proc = self.zen_slice_and_fill(f"Proc:{p_name}", 18)
                    
                    # 3. ラベル - 14文字
                    f_label = self.zen_slice_and_fill(f"[{label}]", 14)
                    
                    # 4. ホスト名（長すぎる場合は末尾を表示した方が役立つことが多いが、今回はシンプルに固定）
                    f_host = host[:40]

                    # 連結
                    line = f"{prefix} {f_proc} | IP:{rid:<15} | Port:{rp:<5} {f_label} | Host:{f_host}"
                    
                    if is_black:
                        self.root.after(0, self.log_to_tab, self.alert_tab, f"【！BLACK！】{line}", "blacklist")
                    elif is_white or rp == 443:
                        tag = "unregistered" if (not is_white and rp == 443) else None
                        self.root.after(0, self.log_to_tab, self.normal_tab, line, tag)
                    else:
                        self.root.after(0, self.log_to_tab, self.alert_tab, f"!!UNKNOWN!!  {line}")
                    
                    self.active_connections[cid] = True

            to_remove = [cid for cid in self.active_connections if cid not in current_found]
            for cid in to_remove: del self.active_connections[cid]
            time.sleep(3)

    def start(self):
        threading.Thread(target=self.monitor, daemon=True).start()
        self.root.mainloop()

if __name__ == "__main__":
    app = CompactZenWatcher()
    app.start()