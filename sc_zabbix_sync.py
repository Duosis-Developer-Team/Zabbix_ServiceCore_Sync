import os
import json
import requests
import urllib3
import socket
import re
import time
import concurrent.futures
from datetime import datetime

# 1. SSL Uyarılarını Sustur
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIG =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL") # DOMAIN OLMALI
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# DNS HACK (Hız ve Erişim İçin Şart)
ZBX_DOMAIN = "watchman.bulutistan.com"
ZBX_REAL_IP = "10.6.116.178"

# ServiceCore Ayarları
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "83"))

# ================= DNS OVERRIDE =================
prv_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args):
    if args[0] == ZBX_DOMAIN:
        return prv_getaddrinfo(ZBX_REAL_IP, *args[1:])
    return prv_getaddrinfo(*args)
socket.getaddrinfo = new_getaddrinfo

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        r = requests.post(ZBX_API_URL, json=payload, timeout=10, verify=False)
        return r.json().get('result')
    except: return None

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data, timeout=5, verify=False)
        else:
            r = requests.post(url, headers=headers, json=data, timeout=5, verify=False) if method == 'POST' else requests.put(url, headers=headers, json=data, timeout=5, verify=False)
        return r
    except: return None

# ================= CORE LOGIC =================

def get_active_problems_with_ticket_ids():
    """
    Zabbix'teki aktif problemleri ve mesajlarını çeker.
    Mesajların içinden 'ServiceCoreID=12345' bilgisini ayıklar.
    """
    log("Zabbix'ten aktif problemler ve mesajlar çekiliyor...")
    
    params = {
        "output": ["eventid", "name"],
        "selectAcknowledges": "extend", # Mesajları da getir
        "recent": False,                # Sadece aktifler
        "sortfield": ["eventid"],
        "sortorder": "DESC"
    }
    
    problems = zbx_req("problem.get", params)
    if not problems: return []
    
    targets = []
    
    for p in problems:
        event_id = p.get('eventid')
        acks = p.get('acknowledges', [])
        
        ticket_id = None
        
        # Mesajların içinde ID ara
        for ack in acks:
            msg = ack.get('message', '')
            # Regex ile ServiceCoreID=12345 yakala
            match = re.search(r'ServiceCoreID\s*=\s*(\d+)', msg, re.IGNORECASE)
            if match:
                ticket_id = match.group(1)
                break
        
        if ticket_id:
            targets.append({"event_id": event_id, "ticket_id": ticket_id})
            
    return targets

def check_and_reopen(target):
    """Tek bir hedefi kontrol et"""
    t_id = target['ticket_id']
    e_id = target['event_id']
    
    # Direkt Ticket'a git (Arama yok!)
    res = sc_req('GET', f'Incident/GetById/{t_id}')
    
    if res and res.status_code == 200:
        try:
            data = res.json().get('Data', {})
            status = data.get('StatusId')
            
            # Eğer Kapalıysa (2) -> REOPEN
            if status in SC_STATUS_CLOSED_IDS:
                log(f"⚠️ UYUŞMAZLIK: Ticket {t_id} Kapalı / Alarm {e_id} Aktif. Açılıyor...")
                
                # Tekrar Aç
                reopen_res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
                    "ticketId": t_id, "statusId": SC_STATUS_REOPEN_ID, "closeReasonId": None
                })
                
                if reopen_res and reopen_res.json().get('IsSuccessfull'):
                    log(f"✅ Ticket {t_id} başarıyla tekrar açıldı.")
                    
                    # Not Ekle
                    sc_req('POST', f'Incident/{t_id}/Conversations/Add', {
                        "description": f"OTOMASYON: Zabbix alarmı ({e_id}) hala aktif olduğu için ticket tekrar açıldı.",
                        "isPrivate": True, "noteType": 1
                    })
                    # Zabbix'e Mesaj At
                    zbx_req("event.acknowledge", {
                        "eventids": [e_id], "action": 4, 
                        "message": f"AWX Automation: Ticket {t_id} re-opened."
                    })
        except:
            pass

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URL eksik.")
        exit(1)

    log("--- ServiceCore Sync (Smart Mode) ---")
    
    # 1. Zabbix'ten ID'leri al
    targets = get_active_problems_with_ticket_ids()
    
    if not targets:
        log("Zabbix'te aktif olup ServiceCoreID içeren kayıt bulunamadı.")
    else:
        log(f"Kontrol edilecek eşleşme sayısı: {len(targets)}")
        
        # 2. Hızlıca Kontrol Et (Multi-Thread)
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_and_reopen, targets)
            
    log("--- Bitti ---")

