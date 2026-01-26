import socket
import time

# Zabbix Bilgileri
TARGET_IP = "10.6.116.178"
TARGET_PORT = 443

print(f"--- BAĞLANTI TESTİ BAŞLIYOR ---")
print(f"Hedef: {TARGET_IP}:{TARGET_PORT}")

try:
    start_time = time.time()
    # 3 saniyelik, kısa bir bağlantı denemesi
    sock = socket.create_connection((TARGET_IP, TARGET_PORT), timeout=3)
    elapsed = time.time() - start_time
    
    print(f"✅ BAŞARILI! Bağlantı kuruldu.")
    print(f"⏱️ Süre: {elapsed:.4f} saniye")
    sock.close()
    
except socket.timeout:
    print(f"❌ HATA: Zaman Aşımı (Timeout)!")
    print(f"   Analiz: Sunucu cevap vermiyor. İstekler Firewall tarafından 'DROP' ediliyor olabilir.")
    
except ConnectionRefusedError:
    print(f"❌ HATA: Bağlantı Reddedildi (Refused)!")
    print(f"   Analiz: Sunucuya ulaştık ama port kapalı veya servis çalışmıyor.")

except Exception as e:
    print(f"❌ HATA: {e}")

print("--- TEST BİTTİ ---")
