# client_ui.py
# UI layout for Secure Messaging Client

import tkinter as tk
from tkinter import ttk, messagebox
from tkinter import scrolledtext


class SecureMessagingClientUI:
    def __init__(self, root, client):
        self.root = root
        self.client = client

        self.root.title("Secure Messaging")
        self.root.geometry("820x600")
        self.root.minsize(700, 500)

        self._build_ui()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.grid(row=0, column=0, sticky="nsew")

        # --- Register Frame ---
        reg = ttk.LabelFrame(main, text="Register", padding=10)
        reg.grid(row=0, column=0, sticky="ew", pady=5)
        reg.columnconfigure(1, weight=1)

        ttk.Label(reg, text="Username:").grid(row=0, column=0, sticky="w")
        self.username_entry = ttk.Entry(reg, width=30)
        self.username_entry.grid(row=0, column=1, sticky="ew")

        ttk.Label(reg, text="Password:").grid(row=1, column=0, sticky="w", pady=5)
        self.password_entry = ttk.Entry(reg, width=30, show="*")
        self.password_entry.grid(row=1, column=1, sticky="ew")

        ttk.Button(reg, text="Select Image", command=self.client.select_image).grid(
            row=2, column=0, pady=3, sticky="w"
        )
        self.image_label = ttk.Label(reg, text="No image selected")
        self.image_label.grid(row=2, column=1, sticky="w")

        ttk.Button(reg, text="Register", command=self.client.register).grid(
            row=3, column=0, pady=5, sticky="w"
        )

        # --- Notebook (tabs for Users & Mail) ---
        notebook = ttk.Notebook(main)
        notebook.grid(row=1, column=0, sticky="nsew", pady=10)

        # Users tab
        users_frame = ttk.Frame(notebook, padding=10)
        notebook.add(users_frame, text="Users")

        self.users_listbox = tk.Listbox(users_frame, height=12)
        self.users_listbox.pack(fill=tk.BOTH, expand=True)
        self.users_listbox.bind("<Double-Button-1>", self.client.open_chat)

        user_btn_frame = ttk.Frame(users_frame)
        user_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(user_btn_frame, text="Refresh", command=self.client.refresh_users).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(user_btn_frame, text="Check Messages", command=self.client.check_messages).pack(
            side=tk.RIGHT, padx=5
        )

        # Mail tab
        mail_frame = ttk.Frame(notebook, padding=10)
        notebook.add(mail_frame, text="Mail")

        self.mail_listbox = tk.Listbox(mail_frame, height=12)
        self.mail_listbox.pack(fill=tk.BOTH, expand=True)

        mail_btn_frame = ttk.Frame(mail_frame)
        mail_btn_frame.pack(fill=tk.X, pady=5)
        ttk.Button(mail_btn_frame, text="Refresh", command=self.client.refresh_mail).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(mail_btn_frame, text="Check Messages", command=self.client.check_messages).pack(
            side=tk.RIGHT, padx=5
        )

        # Status bar
        self.status_label = ttk.Label(main, text="not connected", relief=tk.SUNKEN, anchor="w")
        self.status_label.grid(row=2, column=0, sticky="ew", pady=5)

        # --- resizing config ---
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(1, weight=1)

        notebook.columnconfigure(0, weight=1)
        notebook.rowconfigure(0, weight=1)
class ChatWindow:
    def __init__(self, client, receiver):
        self.client = client
        self.receiver = receiver

        self.win = tk.Toplevel(client.root)
        self.win.title(f"Chat: {receiver}")
        self.win.geometry("520x420")

        # Focus ve olay yönetimi — yalnızca Toplevel açıkken aktif olsun
        self.win.grab_set()
        self.win.focus_force()

        # --- Sohbet ekranı ---
        self.chat_area = scrolledtext.ScrolledText(self.win, wrap=tk.WORD, state="disabled")
        self.chat_area.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Alt kısım (gönderme çubuğu) ---
        frame = ttk.Frame(self.win)
        frame.pack(fill=tk.X, padx=10, pady=5)

        self.entry = tk.Entry(frame)
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.entry.focus_set()
        self.entry.bind("<Return>", lambda e: self.send_message())

        ttk.Button(frame, text="Send", command=self.send_message).pack(side=tk.RIGHT)

    def send_message(self):
        msg = self.entry.get().strip()
        if not msg:
            return
        ok = self.client.send_message(self.receiver, msg)
        if ok:
            self.add_message(f"You: {msg}")
            self.entry.delete(0, tk.END)
        else:
            messagebox.showerror("Error", "Message could not be sent.")

    def add_message(self, text):
        self.chat_area.config(state="normal")
        self.chat_area.insert(tk.END, text + "\n\n")
        self.chat_area.config(state="disabled")
        self.chat_area.see(tk.END)
