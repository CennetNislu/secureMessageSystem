#!/usr/bin/env python3
# client.py
# Secure Messaging Client (optimized + modern UI integration)

import socket
import threading
import json
import base64
import hashlib
import io
import struct
import logging
import queue
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import tkinter as tk
from tkinter import messagebox, filedialog
from client_ui import ChatWindow, SecureMessagingClientUI

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")


# ---- framing helpers ----
def send_json(sock, obj):
    data = json.dumps(obj).encode("utf-8")
    sock.sendall(struct.pack("!I", len(data)) + data)

def recv_json(sock):
    raw_len = recvall(sock, 4)
    if not raw_len:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    data = recvall(sock, msg_len)
    if not data:
        return None
    return json.loads(data.decode("utf-8"))

def recvall(sock, n):
    data = b""
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data


# ---- main client class ----
class SecureMessagingClient:
    def __init__(self, root):
        self.root = root
        self.sock = None
        self.username = None
        self.user_key = None
        self.selected_image = None
        self.connected = False

        # thread control
        self.response_queue = queue.Queue()
        self.sock_lock = threading.Lock()
        self.listener_running = False

        # UI setup (separate file)
        self.ui = SecureMessagingClientUI(root, self)

    # ---- connection management ----
    def connect(self):
        if self.connected:
            return True
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.connect(("localhost", 5555))
            self.connected = True
            self.listener_running = True
            threading.Thread(target=self.listen_loop, daemon=True).start()
            self.ui.status_label.config(text="connected to server")
            return True
        except Exception as e:
            messagebox.showerror("Error", f"Cannot connect to server: {e}")
            return False

    # send + wait pattern
    def send_and_wait(self, obj, timeout=5.0):
        try:
            with self.sock_lock:
                send_json(self.sock, obj)
            try:
                return self.response_queue.get(timeout=timeout)
            except queue.Empty:
                logging.error("Response timeout")
                return None
        except Exception as e:
            logging.exception("send_and_wait error: %s", e)
            return None

    # ---- image & key helpers ----
    def select_image(self):
        path = filedialog.askopenfilename(
            title="Select Image",
            filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")]
        )
        if path:
            self.selected_image = path
            filename = path.split("/")[-1]
            # Hem register hem login ekranındaki label'ları güncelle
            self.ui.reg_image_label.config(text=f"✓ {filename}")

    def embed_key_in_image(self, image_path, key_bytes):
        try:
            img = Image.open(image_path).convert("RGBA")
            pixels = list(img.getdata())
            bits = "".join(f"{b:08b}" for b in key_bytes)
            new_pixels = []
            bit_i = 0
            for p in pixels:
                if bit_i >= len(bits):
                    new_pixels.append(p)
                    continue
                r, g, b, a = p
                if bit_i < len(bits):
                    r = (r & ~1) | int(bits[bit_i])
                    bit_i += 1
                if bit_i < len(bits):
                    g = (g & ~1) | int(bits[bit_i])
                    bit_i += 1
                if bit_i < len(bits):
                    b = (b & ~1) | int(bits[bit_i])
                    bit_i += 1
                new_pixels.append((r, g, b, a))
            new_img = Image.new(img.mode, img.size)
            new_img.putdata(new_pixels)
            buf = io.BytesIO()
            new_img.save(buf, format="PNG")
            return buf.getvalue()
        except Exception as e:
            messagebox.showerror("Error", f"Image embedding error: {e}")
            return None

    def derive_key(self, password):
        h = hashlib.md5(password.encode("utf-8")).digest()
        return h[:8]

    # ---- registration ----
    def register(self):
        username = self.ui.reg_username_entry.get().strip()
        password = self.ui.reg_password_entry.get().strip()
        
        # Placeholder kontrolü
        if username == "Mailinizi Giriniz" or not username:
            messagebox.showwarning("Warning", "Please enter your email")
            return
        if password == "Şifrenizi Giriniz" or not password:
            messagebox.showwarning("Warning", "Please enter your password")
            return
        if not self.selected_image:
            messagebox.showwarning("Warning", "Please select an image")
            return
            
        if not self.connect():
            return
            
        self.user_key = self.derive_key(password)
        stego = self.embed_key_in_image(self.selected_image, self.user_key)
        if not stego:
            return
            
        req = {
            "command": "register",
            "username": username,
            "password": password, # veya hash'lenmiş şekilde
            "image": base64.b64encode(stego).decode("ascii")
        }
        resp = self.send_and_wait(req, timeout=10.0)
        
        if resp and resp.get("status") == "success":
            self.username = username
            messagebox.showinfo("Success", "Registration successful!")
            # Ana ekrana geç
            self.ui.show_main(username)
            self.refresh_users()
            self.refresh_mail()
        else:
            error_msg = resp.get("message", "Unknown error") if resp else "No response from server"
            messagebox.showerror("Error", f"Registration failed: {error_msg}")

    # ---- login ----
    def login(self):
        username = self.ui.login_username_entry.get().strip()
        password = self.ui.login_password_entry.get().strip()
        
        # Placeholder kontrolü
        if username == "Mailinizi Giriniz" or not username:
            messagebox.showwarning("Warning", "Please enter your email")
            return
        if password == "Şifrenizi Giriniz" or not password:
            messagebox.showwarning("Warning", "Please enter your password")
            return
            
        if not self.connect():
            return
            
        self.user_key = self.derive_key(password)
        
        # Login komutu (sunucunuzda login komutu varsa)
        req = {
            "command": "login",
            "username": username,
            "password": password  # veya hash'lenmiş şekilde
        }
        resp = self.send_and_wait(req, timeout=10.0)
        
        if resp and resp.get("status") == "success":
            self.username = username
            messagebox.showinfo("Success", "Login successful!")
            # Ana ekrana geç
            self.ui.show_main(username)
            self.refresh_users()
            self.refresh_mail()
        else:
            error_msg = resp.get("message", "Invalid credentials") if resp else "No response from server"
            messagebox.showerror("Error", f"Login failed: {error_msg}")

    # ---- encryption helpers ----
    def encrypt_message(self, message):
        try:
            key = self.user_key[:8]  # kesin 8 byte
            cipher = DES.new(key, DES.MODE_ECB)
            enc = cipher.encrypt(pad(message.encode("utf-8"), DES.block_size))
            return base64.b64encode(enc).decode("ascii")
        except Exception as e:
            logging.exception(f"encrypt_message error: {e}")
            return None

    def decrypt_message(self, enc_message):
        try:
            key = self.user_key[:8]  # kesin 8 byte
            cipher = DES.new(key, DES.MODE_ECB)
            dec = cipher.decrypt(base64.b64decode(enc_message))
            return unpad(dec, DES.block_size).decode("utf-8")
        except Exception as e:
            logging.exception(f"decrypt_message error: {e}")
            return None

    # ---- communication ----
    def refresh_users(self):
        if not self.connected or not self.username:
            messagebox.showwarning("Warning", "You must be logged in first")
            return
            
        resp = self.send_and_wait({"command": "get_users"}, timeout=5.0)
        if resp and resp.get("status") == "success":
            self.ui.users_listbox.delete(0, tk.END)
            users = resp.get("users", [])
            for u in users:
                if u != self.username:  # Kendini gösterme
                    self.ui.users_listbox.insert(tk.END, u)
            logging.info(f"Refreshed users list: {len(users)} users")
        else:
            logging.warning("Failed to refresh users")

    def refresh_mail(self):
        if not self.connected or not self.username:
            messagebox.showwarning("Warning", "You must be logged in first")
            return
            
        resp = self.send_and_wait({"command": "get_messages"}, timeout=5.0)
        if resp and resp.get("status") == "success":
            self.ui.mail_listbox.delete(0, tk.END)
            messages = resp.get("messages", [])
            for m in messages:
                dec = self.decrypt_message(m["message"])
                if dec is not None:
                    self.ui.mail_listbox.insert(tk.END, f"From {m['from']}: {dec}")
            logging.info(f"Refreshed mail: {len(messages)} messages")
        else:
            logging.warning("Failed to refresh mail")

    def open_chat(self, event):
        sel = self.ui.users_listbox.curselection()
        if not sel:
            return
        receiver = self.ui.users_listbox.get(sel[0])
        ChatWindow(self, receiver)

    def send_message(self, receiver, message):
        if not self.connected or not self.username:
            messagebox.showwarning("Warning", "Not connected")
            return False
            
        if not message or not message.strip():
            messagebox.showwarning("Warning", "Message cannot be empty")
            return False

        # Debug için log ekleyelim
        logging.info(f"Attempting to send message to {receiver}")
        logging.info(f"Connected: {self.connected}, Username: {self.username}")
            
        # Mesaj şifreleme
        enc = self.encrypt_message(message)
        if not enc:
            logging.error("Message encryption failed")
            messagebox.showerror("Error", "Could not encrypt message")
            return False
            
        req = {
            "command": "send_message",
            "sender": self.username,  # Gönderen bilgisini ekleyelim
            "receiver": receiver,
            "message": enc
        }

        logging.info("Sending message request to server...")
        resp = self.send_and_wait(req, timeout=5.0)
        
        if resp is None:
            logging.error("No response from server")
            messagebox.showerror("Error", "No response from server")
            return False
            
        if resp.get("status") == "success":
            logging.info(f"Message successfully sent to {receiver}")
            return True
        else:
            error_msg = resp.get("message", "Unknown error")
            logging.error(f"Failed to send message: {error_msg}")
            messagebox.showerror("Error", f"Failed to send message: {error_msg}")
            return False

    def check_messages(self):
        if not self.connected or not self.username:
            messagebox.showwarning("Warning", "You must be logged in first")
            return
            
        resp = self.send_and_wait({"command": "get_messages"}, timeout=5.0)
        if resp and resp.get("status") == "success":
            messages = resp.get("messages", [])
            if not messages:
                messagebox.showinfo("Messages", "No new messages")
                return
                
            for m in messages:
                dec = self.decrypt_message(m["message"])
                if dec is not None:
                    messagebox.showinfo(f"Message from {m['from']}", dec)
        else:
            messagebox.showerror("Error", "Failed to check messages")

    # ---- listener thread ----
    def listen_loop(self):
        while self.listener_running:
            try:
                msg = recv_json(self.sock)
                if msg is None:
                    logging.info("listen_loop: socket closed or None received")
                    break
                    
                # Yeni mesaj bildirimi
                if isinstance(msg, dict) and msg.get("type") == "new_message":
                    try:
                        dec = self.decrypt_message(msg["message"])
                    except Exception:
                        dec = None
                    if dec:
                        sender = msg.get('from', 'Unknown')
                        self.root.after(0, lambda m=dec, f=sender: 
                                      messagebox.showinfo(f"New Message from {f}", m))
                    continue
                    
                # Normal yanıtları kuyruğa ekle
                self.response_queue.put(msg)
                
            except Exception as e:
                logging.exception("listen_loop error: %s", e)
                break

        # Cleanup
        self.listener_running = False
        self.connected = False
        try:
            if self.sock:
                self.sock.close()
        except:
            pass
        self.root.after(0, lambda: self.ui.status_label.config(
            text="not connected/ disconnected from server"))


# ---- main ----
if __name__ == "__main__":
    root = tk.Tk()
    app = SecureMessagingClient(root)
    root.mainloop()