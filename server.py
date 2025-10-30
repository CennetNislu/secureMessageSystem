#!/usr/bin/env python3
# server.py
# Improved secure messaging server
# ascii only (no turkish characters)

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

DATA_FILE = "server_data.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class SecureMessagingServer:
    def __init__(self, host="localhost", port=5555):
        self.host = host
        self.port = port
        self.server_socket = None
        # users: {username: {'key': bytes, 'socket': socket, 'online': bool}}
        self.users = {}
        # messages: {username: [ {from, message} ] }  encrypted with receiver key
        self.messages = {}
        # socket->username
        self.clients = {}
        self.lock = threading.Lock()
        self.load_data()

    def save_data(self):
        try:
            data = {
                "users": {u: {"key": base64.b64encode(info["key"]).decode("ascii")} for u, info in self.users.items()},
                "messages": self.messages
            }
            with open(DATA_FILE, "w") as f:
                json.dump(data, f)
            logging.info("data saved to %s", DATA_FILE)
        except Exception as e:
            logging.exception("save_data error: %s", e)

    def load_data(self):
        if not os.path.exists(DATA_FILE):
            return
        try:
            with open(DATA_FILE, "r") as f:
                data = json.load(f)
            users = data.get("users", {})
            for u, info in users.items():
                key = base64.b64decode(info["key"])
                self.users[u] = {"key": key, "socket": None, "online": False}
            self.messages = data.get("messages", {})
            logging.info("loaded data from %s", DATA_FILE)
        except Exception as e:
            logging.exception("load_data error: %s", e)

    # ---- framing helpers: send/recv with 4-byte length prefix ----
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

    # ---- stego extraction ----
    def extract_key_from_image(self, image_data):
        try:
            image = Image.open(io.BytesIO(image_data)).convert("RGBA")
            pixels = list(image.getdata())
            # We will read first 64 bits (8 bytes) from the LSBs of channels R,G,B sequentially.
            bits = []
            for p in pixels:
                r,g,b,a = p
                bits.append(r & 1)
                if len(bits) >= 64: break
                bits.append(g & 1)
                if len(bits) >= 64: break
                bits.append(b & 1)
                if len(bits) >= 64: break
            # make bytes
            key_bytes = bytearray()
            for i in range(0, 64, 8):
                byte = 0
                for j in range(8):
                    byte = (byte << 1) | bits[i + j]
                key_bytes.append(byte)
            return bytes(key_bytes)
        except Exception as e:
            logging.exception("extract_key_from_image error: %s", e)
            return None

    # ---- DES helpers ----
    def encrypt_message(self, message, key):
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            padded = pad(message.encode("utf-8"), DES.block_size)
            encrypted = cipher.encrypt(padded)
            return base64.b64encode(encrypted).decode("ascii")
        except Exception as e:
            logging.exception("encrypt_message error: %s", e)
            return None

    def decrypt_message(self, encrypted_message, key):
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            encrypted_bytes = base64.b64decode(encrypted_message)
            decrypted = cipher.decrypt(encrypted_bytes)
            unpadded = unpad(decrypted, DES.block_size)
            return unpadded.decode("utf-8")
        except Exception as e:
            logging.exception("decrypt_message error: %s", e)
            return None

    # ---- handlers ----
    def handle_register(self, client_socket, data):
        try:
            username = data["username"]
            image_b64 = data["image"]
            image_data = base64.b64decode(image_b64)
            key = self.extract_key_from_image(image_data)
            if not key:
                self.send_json(client_socket, {"status": "error", "message": "key not extracted"})
                return
            with self.lock:
                self.users[username] = {"key": key, "socket": client_socket, "online": True}
                self.clients[client_socket] = username
                if username not in self.messages:
                    self.messages[username] = []
            self.save_data()
            self.send_json(client_socket, {"status": "success", "message": "registered"})
            logging.info("user registered: %s", username)
        except Exception as e:
            logging.exception("handle_register error: %s", e)

    def handle_get_users(self, client_socket):
        try:
            with self.lock:
                current = self.clients.get(client_socket, None)
                users = [u for u in self.users.keys() if u != current]
            self.send_json(client_socket, {"status": "success", "users": users})
        except Exception as e:
            logging.exception("handle_get_users error: %s", e)

    def handle_send_message(self, client_socket, data):
        try:
            sender = self.clients.get(client_socket)
            receiver = data.get("receiver")
            encrypted_message = data.get("message")
            if not sender or not receiver or not encrypted_message:
                self.send_json(client_socket, {"status": "error", "message": "invalid parameters"})
                return
            # decrypt with sender key
            sender_key = self.users[sender]["key"]
            plain = self.decrypt_message(encrypted_message, sender_key)
            if plain is None:
                self.send_json(client_socket, {"status": "error", "message": "cannot decrypt with sender key"})
                return
            logging.info("%s -> %s: %s", sender, receiver, plain)
            # re-encrypt with receiver key
            if receiver not in self.users:
                self.send_json(client_socket, {"status": "error", "message": "unknown receiver"})
                return
            receiver_key = self.users[receiver]["key"]
            re_enc = self.encrypt_message(plain, receiver_key)
            with self.lock:
                self.messages.setdefault(receiver, []).append({"from": sender, "message": re_enc})
            # if receiver online send notification
            with self.lock:
                if self.users[receiver].get("online") and self.users[receiver].get("socket"):
                    try:
                        notif = {"type": "new_message", "from": sender, "message": re_enc}
                        self.send_json(self.users[receiver]["socket"], notif)
                    except Exception as e:
                        logging.exception("notify error: %s", e)
            self.save_data()
            self.send_json(client_socket, {"status": "success", "message": "sent"})
        except Exception as e:
            logging.exception("handle_send_message error: %s", e)

    def handle_get_messages(self, client_socket):
        try:
            username = self.clients.get(client_socket)
            if not username:
                self.send_json(client_socket, {"status": "error", "message": "unknown client"})
                return
            with self.lock:
                pending = self.messages.get(username, []).copy()
                self.messages[username] = []
            self.save_data()
            self.send_json(client_socket, {"status": "success", "messages": pending})
        except Exception as e:
            logging.exception("handle_get_messages error: %s", e)

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
                username = self.clients.pop(client_socket, None)
                if username and username in self.users:
                    self.users[username]["online"] = False
                    self.users[username]["socket"] = None
                    logging.info("disconnected: %s", username)
            client_socket.close()

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
            self.server_socket.close()

if __name__ == "__main__":
    s = SecureMessagingServer()
    s.start()
