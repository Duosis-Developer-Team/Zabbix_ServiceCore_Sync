import os
import json
import requests
import urllib3
import socket
import time
from datetime import datetime

# SSL Uyarılarını Gizle
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIG =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL") # DOMAIN OLMALI (watchman.bulutistan.com)
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# --- MANUEL DNS AYARI ---
# Test sonucundan aldığımız çalışan IP'yi buraya yazıyoruz
ZBX_DOMAIN = "watchman.bulutistan.com"
ZBX_REAL_IP = "10.6.116.178" 

# ServiceCore Ayarları
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))
SC_FIELD_KEY = os.getenv("SC_FIELD_KEY", "Eventid") 

# ================= DEBUG LOGGER =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

# ================= DNS OVERRIDE (YENİLENMİŞ) =================
# Bu kısım Requests kütüphanesini kandırarak Domain isteğini IP'ye çevirir.
# SSL (SNI) Domain olarak kalır, ama paket IP'ye gider.

# Orijinal fonksiyonu sakla
prv_getaddrinfo = socket.getaddrinfo

def new_getaddrinfo(*args):
    host = args[0]
    # Eğer sorgulanan adres bizim Zabbix Domain ise
    if host == ZBX_DOMAIN:
        # log(f"DEBUG: DNS Override Devrede! {host} -> {ZBX_REAL_IP}")
        # Port ve diğer bilgileri koruyarak IP'yi döndür
        return prv_getaddrinfo(ZBX_REAL_IP, *args[1:])
    return prv_getaddrinfo(*args)

# Fonksiyonu değiştir
socket.getaddrinfo = new_getaddrinfo
# =============================================================

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        log(f"   -> Zabbix İsteği Gönderiliyor: {method}")
        start = time.time()
        
        # Timeout 10sn verildi. verify=False ile sertifika hatası engellendi.
        r = requests.post(ZBX_API_URL, json=payload, timeout=10, verify=False)
        
        duration = time.time() - start
        log(f"   <- Zabbix Cevap Döndü ({duration:.2f}s). HTTP {r.status_code}")
        
        return r.json().get('result')
    except Exception as e:
        log(f"❌ Zabbix Hatası: {e}")
        return None

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data, timeout=10, verify=False)
        else:
            r = requests.post(url, headers=headers, json=data, timeout=10, verify=False) if method == 'POST' else requests.put(url, headers=headers, json=data, timeout=10, verify=False)
        return r
    except Exception as e:
        log(f"SC Hatası: {e}")
        return None

# ================= ANA MANTIK =================

def get_active_zabbix_problems():
    log(f"Zabbix'e bağlanılıyor... ({ZBX_DOMAIN} -> {ZBX_REAL_IP})")
    
    # Sadece aktif (çözülmemiş) problemleri getir
    params = {
        "output": ["eventid", "name"],
        "recent": False,
        "sortfield": ["eventid"],
        "sortorder": "DESC"
    }
    problems = zbx_req("problem.get", params)
    
    if problems is None:
        log("⚠️ Zabbix'ten veri alınamadı.")
        return []
    return problems

def find_ticket_by_event_id(event_id):
    # ServiceCore'da bu Event ID'yi ara
    payload = {
        "fieldKey": SC_FIELD_KEY,
        "fieldValue": str(event_id),
        "isAddUtcHours": False, "addUtcHours": 0, "minusSecondValue": 0, "dataKey": ""
    }
    res = sc_req('POST', 'Incident/SearchIncidentByCustomField', payload)
    
    if res and res.status_code == 200:
        try:
            j = res.json()
            if j.get('IsSuccessfull'):
                return j.get('Data')
        except: pass
    return None

def reopen_ticket(ticket_id, event_id):
    log(f"🔧 Ticket {ticket_id} tekrar açılıyor...")
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id, "statusId": SC_STATUS_REOPEN_ID, "closeReasonId": None
    })
    
    if res and res.json().get('IsSuccessfull'):
        log(f"✅ BAŞARILI: Ticket {ticket_id} AÇILDI.")
        
        # Not düş
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": f"OTOMASYON: Zabbix alarmı (Event: {event_id}) aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        
        # Zabbix Ack
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: ServiceCore Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"❌ HATA: Ticket açılamadı.")

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URL'leri eksik.")
        exit(1)

    log("--- Zabbix Sync Başlatılıyor ---")
    
    # 1. Zabbix Aktif Problemleri Al
    active_problems = get_active_zabbix_problems()
    
    if not active_problems:
        log("Zabbix'te aktif problem yok veya bağlantı başarısız.")
    else:
        log(f"🔍 Zabbix'te {len(active_problems)} adet aktif problem bulundu. Kontrol ediliyor...")
        
        for problem in active_problems:
            eid = problem.get('eventid')
            name = problem.get('name')
            
            # ServiceCore Kontrolü
            found_data = find_ticket_by_event_id(eid)
            
            tickets = []
            if isinstance(found_data, list): tickets = found_data
            elif isinstance(found_data, dict): tickets = [found_data]
            
            if not tickets:
                continue
                
            for t in tickets:
                t_id = t.get('Id') or t.get('TicketId')
                status_id = t.get('StatusId')
                
                # Ticket KAPALI (2) ama Zabbix AKTİF -> AÇ
                if status_id in SC_STATUS_CLOSED_IDS:
                    log(f"⚠️ UYUŞMAZLIK: Ticket {t_id} Kapalı ama Zabbix Alarmı ({eid}) Aktif!")
                    reopen_ticket(t_id, eid)

    log("--- İşlem Tamamlandı ---")
