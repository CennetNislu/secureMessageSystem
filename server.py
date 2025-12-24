#!/usr/bin/env python3
# server.py
# Improved secure messaging server
# ascii only (no turkish characters)
# Secure messaging server with SQLite storage, register/login with password + image

import socket
import threading
import json
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from PIL import Image
import io
import os
import struct
import logging
import sqlite3
import hashlib
import time

DB_FILE = "server2.db"
IMAGE_DIR = "user_images"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class SecureMessagingServer:
    def __init__(self, host="localhost", port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        # socket -> username
        self.clients = {}
        self.lock = threading.Lock()
        os.makedirs(IMAGE_DIR, exist_ok=True)
        self.ensure_tables()

    # ---- database setup ----
    def ensure_tables(self):
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        # create users table with expected columns
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            salt TEXT,
            key TEXT,
            image_path TEXT
        )
        ''')
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            encrypted_message TEXT,
            steg_image_path TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        ''')
        conn.commit()

        # Compatibility: if older DB exists with missing columns, try to add them
        cursor.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cursor.fetchall()}
        needed = {"password_hash", "salt", "key", "image_path"}
        for col in needed - cols:
            try:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {col} TEXT")
                logging.info("added missing column %s to users table", col)
            except Exception as e:
                logging.exception("could not add column %s: %s", col, e)
        conn.commit()
        conn.close()

    # ---- password helpers ----
    def hash_password(self, password, salt=None):
        if salt is None:
            salt = os.urandom(16)
        else:
            salt = base64.b64decode(salt)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return base64.b64encode(dk).decode("ascii"), base64.b64encode(salt).decode("ascii")

    def verify_password(self, password, stored_hash_b64, stored_salt_b64):
        try:
            dk, _ = self.hash_password(password, salt=stored_salt_b64)
            return dk == stored_hash_b64
        except Exception as e:
            logging.exception("verify_password error: %s", e)
            return False

    # ---- user / db helpers ----
    def add_user(self, username, key_bytes, password_hash_b64, salt_b64, image_path):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            b64key = base64.b64encode(key_bytes).decode("ascii")
            cursor.execute("""
                INSERT INTO users (username, password_hash, salt, key, image_path)
                VALUES (?, ?, ?, ?, ?)
            """, (username, password_hash_b64, salt_b64, b64key, image_path))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False
        except Exception as e:
            logging.exception("add_user error: %s", e)
            return False
        finally:
            conn.close()

    def get_user_record(self, username):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT username, password_hash, salt, key, image_path FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            if not row:
                return None
            return {
                "username": row[0],
                "password_hash": row[1],
                "salt": row[2],
                "key_b64": row[3],
                "image_path": row[4]
            }
        except Exception as e:
            logging.exception("get_user_record error: %s", e)
            return None
        finally:
            conn.close()

    def get_user_key(self, username):
        rec = self.get_user_record(username)
        if not rec or not rec.get("key_b64"):
            return None
        try:
            return base64.b64decode(rec["key_b64"])
        except Exception as e:
            logging.exception("get_user_key error: %s", e)
            return None

    def get_all_users(self):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users")
            rows = cursor.fetchall()
            return [r[0] for r in rows]
        except Exception as e:
            logging.exception("get_all_users error: %s", e)
            return []
        finally:
            conn.close()

    def save_message(self, sender, receiver, encrypted_message, steg_path=None):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO messages (sender, receiver, encrypted_message, steg_image_path)
                VALUES (?, ?, ?, ?)
            """, (sender, receiver, encrypted_message, steg_path))
            conn.commit()
        except Exception as e:
            logging.exception("save_message error: %s", e)
        finally:
            conn.close()

    # server.py içindeki düzeltilmiş fonksiyon
    def get_user_messages(self, username):
        try:
            conn = sqlite3.connect(DB_FILE)
            cursor = conn.cursor()
            
            # Mesajları tarihe göre sıralı çekelim
            cursor.execute("""
                SELECT sender, encrypted_message, timestamp 
                FROM messages 
                WHERE receiver = ? 
                ORDER BY timestamp ASC
            """, (username,))
            
            rows = cursor.fetchall()
            
            # BU SATIRI SİLDİK: cursor.execute("DELETE FROM messages WHERE receiver = ?", (username,))
            
            conn.commit() # Select işleminde commit şart değil ama connection yönetimi için kalsın
            
            # Timestamp bilgisini de dönebilirsiniz, şimdilik eski yapıya sadık kalarak dönüyoruz
            return [{"from": s, "message": m} for s, m, t in rows]
        except Exception as e:
            logging.exception("get_user_messages error: %s", e)
            return []
        finally:
            conn.close()

    # ---- framing helpers ----
    def send_json(self, sock, obj):
        try:
            data = json.dumps(obj).encode("utf-8")
            sock.sendall(struct.pack("!I", len(data)) + data)
        except Exception as e:
            logging.exception("send_json error: %s", e)

    def recv_json(self, sock):
        try:
            raw_len = self.recvall(sock, 4)
            if not raw_len:
                return None
            msg_len = struct.unpack("!I", raw_len)[0]
            data = self.recvall(sock, msg_len)
            if not data:
                return None
            return json.loads(data.decode("utf-8"))
        except Exception as e:
            logging.exception("recv_json error: %s", e)
            return None

    def recvall(self, sock, n):
        data = b""
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    # ---- stego helpers (extraction kept, embedding placeholder) ----
    def extract_key_from_image(self, image_data):
        """LSB yöntemiyle resmin ilk 64 bitinden 8 byte'lık anahtarı çıkarır[cite: 197, 199]."""
        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGB")
            pixels = list(image.getdata())
            bits = ""
            for p in pixels:
                for color_val in p[:3]: # R, G, B değerlerini tara
                    bits += str(color_val & 1)
                    if len(bits) >= 64: break
                if len(bits) >= 64: break
            
            key_bytes = bytearray()
            for i in range(0, 64, 8):
                key_bytes.append(int(bits[i:i+8], 2))
            return bytes(key_bytes)
        except Exception as e:
            logging.error(f"Anahtar çıkarma hatası: {e}")
            return None

    # Placeholder for future embedding (not modifying now as you requested)
    def embed_key_into_image(self, image_data, key_bytes):
        # For now return original image_data (embedding deferred)
        return image_data

    # ---- DES helpers ----
    def encrypt_message(self, message, key):
        try:
            key = key[:8]  # kesin 8 byte
            cipher = DES.new(key, DES.MODE_ECB)
            padded = pad(message.encode("utf-8"), DES.block_size)
            encrypted = cipher.encrypt(padded)
            return base64.b64encode(encrypted).decode("ascii")
        except Exception as e:
            logging.exception(f"encrypt_message error: {e}")
            return None

    def decrypt_message(self, encrypted_message, key):
        try:
            key = key[:8]  # kesin 8 byte
            cipher = DES.new(key, DES.MODE_ECB)
            encrypted_bytes = base64.b64decode(encrypted_message)
            decrypted = cipher.decrypt(encrypted_bytes)
            unpadded = unpad(decrypted, DES.block_size)
            return unpadded.decode("utf-8")
        except Exception as e:
            logging.exception(f"decrypt_message error: {e}")
            return None

    # ---- command handlers ----
    def handle_register(self, client_socket, data):
        try:
            username = data.get("username")
            password = data.get("password")
            image_b64 = data.get("image")
            if not username or not password or not image_b64:
                self.send_json(client_socket, {"status": "error", "message": "missing fields"})
                return

            # check exists
            if self.get_user_record(username):
                self.send_json(client_socket, {"status": "error", "message": "username exists"})
                return

            # decode image
            try:
                image_data = base64.b64decode(image_b64)
            except Exception:
                self.send_json(client_socket, {"status": "error", "message": "invalid image encoding"})
                return

            ts = int(time.time())
            fname = f"{username}_{ts}.png"
            fpath = os.path.join(IMAGE_DIR, fname)
            try:
                with open(fpath, "wb") as f:
                    f.write(image_data)
            except Exception as e:
                logging.exception("saving image failed: %s", e)
                self.send_json(client_socket, {"status": "error", "message": "image save failed"})
                return

            # TRY to extract key from image (client embeds key)
            key_bytes = self.extract_key_from_image(image_data)
            if not key_bytes or len(key_bytes) < 8:
                logging.warning("could not extract key from image or key too short; falling back to random key")
                key_bytes = os.urandom(8)
            else:
                # ensure exactly 8 bytes
                key_bytes = key_bytes[:8]

            # hash password
            password_hash_b64, salt_b64 = self.hash_password(password)

            ok = self.add_user(username, key_bytes, password_hash_b64, salt_b64, fpath)
            if not ok:
                self.send_json(client_socket, {"status": "error", "message": "could not create user"})
                try: os.remove(fpath)
                except: pass
                return

            with self.lock:
                self.clients[client_socket] = username

            self.send_json(client_socket, {"status": "success", "message": "registered"})
            logging.info("user registered: %s (key from image: %s)", username, "yes" if key_bytes else "no")
        except Exception as e:
            logging.exception("handle_register error: %s", e)
            self.send_json(client_socket, {"status": "error", "message": "server error"})
        
    def handle_login(self, client_socket, data):
        try:
            username = data.get("username")
            password = data.get("password")
            if not username or not password:
                self.send_json(client_socket, {"status": "error", "message": "missing username/password"})
                return
            rec = self.get_user_record(username)
            if not rec:
                self.send_json(client_socket, {"status": "error", "message": "unknown user"})
                return
            if not self.verify_password(password, rec["password_hash"], rec["salt"]):
                self.send_json(client_socket, {"status": "error", "message": "invalid credentials"})
                return
            with self.lock:
                self.clients[client_socket] = username
            self.send_json(client_socket, {"status": "success", "message": "logged_in"})
            logging.info("user logged in: %s", username)
        except Exception as e:
            logging.exception("handle_login error: %s", e)
            self.send_json(client_socket, {"status": "error", "message": "server error"})

    def handle_get_users(self, client_socket):
        try:
            with self.lock:
                current = self.clients.get(client_socket, None)
            users = self.get_all_users()
            users = [u for u in users if u != current]
            self.send_json(client_socket, {"status": "success", "users": users})
        except Exception as e:
            logging.exception("handle_get_users error: %s", e)

    def handle_send_message(self, client_socket, data):
        """Ödev protokolüne göre: C1 anahtarıyla çöz, C2 anahtarıyla şifrele."""
        try:
            sender = self.clients.get(client_socket)
            receiver = data.get("receiver")
            enc_msg_from_c1 = data.get("message")
            
            # 1. Her iki kullanıcının anahtarını DB'den al 
            sender_key = self.get_user_key(sender)
            receiver_key = self.get_user_key(receiver)
            
            if not sender_key or not receiver_key:
                self.send_json(client_socket, {"status": "error", "message": "Kullanıcı anahtarı bulunamadı."})
                return

            # 2. Mesajı gönderenin (C1) anahtarıyla çöz [cite: 208]
            plain_text = self.decrypt_message(enc_msg_from_c1, sender_key)
            if plain_text is None:
                self.send_json(client_socket, {"status": "error", "message": "Mesaj deşifre edilemedi."})
                return

            # 3. Mesajı alıcının (C2) anahtarıyla tekrar şifrele [cite: 209]
            re_encrypted_msg = self.encrypt_message(plain_text, receiver_key)
            
            # 4. Veritabanına kaydet (Offline mesajlaşma desteği) [cite: 203, 210]
            self.save_message(sender, receiver, re_encrypted_msg)

            # 5. Alıcı online ise ona ilet [cite: 213]
            with self.lock:
                for sock, user in self.clients.items():
                    if user == receiver:
                        self.send_json(sock, {"type": "new_message", "from": sender, "message": re_encrypted_msg})
            
            self.send_json(client_socket, {"status": "success", "message": "Mesaj iletildi."})
        except Exception as e:
            logging.exception("handle_send_message error")

    def handle_get_messages(self, client_socket):
        try:
            username = self.clients.get(client_socket)
            if not username:
                self.send_json(client_socket, {"status": "error", "message": "unknown client"})
                return
            
            pending = self.get_user_messages(username)
            self.send_json(client_socket, {"status": "success", "messages": pending})
        except Exception as e:
            logging.exception("handle_get_messages error: %s", e)

    # ---- main loop ----
    def handle_client(self, client_socket, address):
        logging.info("new connection: %s", address)
        try:
            while True:
                req = self.recv_json(client_socket)
                if req is None:
                    break
                cmd = req.get("command")
                if cmd == "register":
                    self.handle_register(client_socket, req)
                elif cmd == "login":
                    self.handle_login(client_socket, req)
                elif cmd == "get_users":
                    self.handle_get_users(client_socket)
                elif cmd == "send_message":
                    self.handle_send_message(client_socket, req)
                elif cmd == "get_messages":
                    self.handle_get_messages(client_socket)
                else:
                    self.send_json(client_socket, {"status": "error", "message": "unknown command"})
        except Exception as e:
            logging.exception("client loop error: %s", e)
        finally:
            with self.lock:
                user = self.clients.pop(client_socket, None)
                if user:
                    logging.info("disconnected: %s", user)
            try:
                client_socket.close()
            except:
                pass

    def start(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(10)
        logging.info("server started on %s:%s", self.host, self.port)
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                t = threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True)
                t.start()
        except KeyboardInterrupt:
            logging.info("server stopping...")
        finally:
            try:
                self.server_socket.close()
            except:
                pass

if __name__ == "__main__":
    s = SecureMessagingServer()
    s.start()
