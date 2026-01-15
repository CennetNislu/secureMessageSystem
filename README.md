# 🔐 Güvenli Mesajlaşma Protokolü
## DES Şifreleme ve LSB Steganografi Tabanlı İstemci–Sunucu Uygulaması

## 📌 Proje Tanımı
Bu proje, **Bilgi Güvenliği** dersi kapsamında tasarlanmış bir **güvenli mesajlaşma protokolüdür**. Sistem, bir sunucuya bağlı **birden fazla istemcinin (client)** güvenli şekilde haberleşmesini sağlayacak şekilde geliştirilmiştir.

Protokolde;
- **Mesaj gizliliği** DES şifreleme algoritması ile,
- **Kullanıcı anahtarının güvenli iletimi** ise LSB steganografi yöntemi ile
sağlanmaktadır.

Sistem, çevrim içi (online) ve çevrim dışı (offline) mesajlaşmayı desteklemektedir.

---

## 🎯 Projenin Amacı
- Çok kullanıcılı bir istemci–sunucu mesajlaşma sistemi tasarlamak  
- Kriptografi ve steganografiyi birlikte kullanan bir güvenli protokol geliştirmek  
- Anahtar paylaşım problemini steganografi ile çözmek  
- Bilgi güvenliği kavramlarını uygulamalı olarak göstermek  

---

## 🏗️ Sistem Mimarisi
Sistem üç ana bileşenden oluşur:
- **Sunucu (Server)**
- **İstemciler (Clients)**
- **Mesaj Depolama Yapısı (Mailbox / Veri Yapısı)**

Sunucu, aynı anda birden fazla istemcinin sisteme kayıt olmasını ve birbirleriyle güvenli şekilde mesajlaşmasını sağlar.

---

## 🧠 Kullanılan Yöntemler

### 🔑 DES Şifreleme
- Simetrik anahtarlı şifreleme algoritmasıdır.
- Mesajların gizliliğini sağlamak için kullanılır.
- Her kullanıcıya ait özel bir anahtar bulunmaktadır.

### 🖼️ LSB Steganografi (Anahtar Gizleme)
- Kullanıcının seçtiği parola, LSB yöntemi ile kullanıcının yüklediği görüntü içerisine gizlenir.
- Anahtar, açık biçimde ağ üzerinden gönderilmez.
- Böylece anahtarın varlığı gizlenmiş olur.

---

## 📝 Kullanıcı Kayıt (Register) Süreci
1. İstemci, kullanıcı adı, parola ve bir görüntü dosyası girer  
2. Parola, istemci tarafında LSB steganografi yöntemi ile görüntü içine gizlenir  
3. Oluşturulan steganografik görüntü sunucuya gönderilir  
4. Sunucu, görüntü içinden anahtar bilgisini çıkarır  
5. Anahtar, ilgili kullanıcı adı ile eşleştirilerek sunucu tarafında saklanır  

---

## 💬 Mesajlaşma Süreci

### Kullanıcı Seçimi
- Sunucu, aktif veya kayıtlı tüm kullanıcıların listesini istemcilere gönderir
- İstemci, listeden mesaj göndermek istediği kullanıcıyı seçer

### Mesaj Gönderme
1. Gönderen istemci (C1), mesajı kendi anahtarı ile **DES kullanarak şifreler**
2. Şifreli mesaj sunucuya gönderilir
3. Sunucu, mesajın C1’den geldiğini bildiği için C1’in anahtarıyla mesajı çözer
4. Sunucu, mesajı alıcı (C2) için C2’nin anahtarı ile tekrar şifreler
5. Şifreli mesaj, C2’nin mesaj kutusuna eklenir

---

## 📦 Offline Mesajlaşma Desteği
- Alıcı istemci (C2) çevrim dışı olabilir
- Mesajlar sunucu tarafında saklanır
- C2 online olduğunda, bekleyen mesajlar C2’ye gönderilir
- C2 istemcisi, kendi anahtarı ile gelen mesajı çözer

---

## 🛠️ Kullanılan Teknolojiler
- Python 
- DES şifreleme kütüphaneleri
- LSB Steganografi
- Socket Programming
- İstemci–Sunucu Mimarisi

---

## 📚 Ders Kapsamı
Bu proje aşağıdaki bilgi güvenliği konularını içermektedir:
- Simetrik anahtarlı şifreleme
- Steganografi ile anahtar gizleme
- Güvenli mesajlaşma protokolleri
- İstemci–sunucu haberleşmesi
- Offline mesajlaşma mantığı

---

## ⚠️ Not
Bu proje **akademik amaçlıdır**. Gerçek sistemlerde DES yerine AES gibi daha güçlü algoritmalar ve gelişmiş anahtar yönetim mekanizmaları tercih edilmelidir.
