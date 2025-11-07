import sqlite3

# Veritabanı dosyasını oluşturur (yoksa otomatik yaratır)
conn = sqlite3.connect("server.db")
cursor = conn.cursor()

# Kullanıcılar tablosu
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
)
''')

# Mesajlar tablosu
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
conn.close()

print("✅ Veritabanı ve tablolar başarıyla oluşturuldu.")
