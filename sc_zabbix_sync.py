import os
import json
import requests
import urllib3
import socket
import time
import concurrent.futures
from datetime import datetime

# 1. SSL Uyarılarını Sustur
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIG =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL") # Credential'da DOMAIN yazmalı
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# --- MANUEL DNS AYARI (Testten gelen IP) ---
ZBX_DOMAIN = "watchman.bulutistan.com"
ZBX_REAL_IP = "10.6.116.178"

# ServiceCore Ayarları
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))
SC_FIELD_KEY = os.getenv("SC_FIELD_KEY", "Eventid") 

# HIZ AYARI: Aynı anda kaç sorgu atılsın?
MAX_WORKERS = 20

# ================= DNS OVERRIDE =================
prv_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args):
    if args[0] == ZBX_DOMAIN:
        return prv_getaddrinfo(ZBX_REAL_IP, *args[1:])
    return prv_getaddrinfo(*args)
socket.getaddrinfo = new_getaddrinfo
# ============================================

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        # Timeout'u kısalttık, takılmasın
        r = requests.post(ZBX_API_URL, json=payload, timeout=10, verify=False)
        return r.json().get('result')
    except:
        return None

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data, timeout=5, verify=False)
        else:
            r = requests.post(url, headers=headers, json=data, timeout=5, verify=False) if method == 'POST' else requests.put(url, headers=headers, json=data, timeout=5, verify=False)
        return r
    except:
        return None

# ================= CORE LOGIC =================

def get_active_zabbix_problems():
    log(f"Zabbix aktif problemler çekiliyor...")
    params = {
        "output": ["eventid", "name"],
        "recent": False,           # Sadece şu an bozuk olanlar
        "sortfield": ["eventid"],
        "sortorder": "DESC",
        "limit": 1000              # Güvenlik limiti: En son 1000 problem
    }
    problems = zbx_req("problem.get", params)
    return problems or []

def find_ticket_by_event_id(event_id):
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
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id, "statusId": SC_STATUS_REOPEN_ID, "closeReasonId": None
    })
    
    if res and res.json().get('IsSuccessfull'):
        log(f"✅ ACTION: Ticket {ticket_id} AÇILDI (Event: {event_id})")
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": f"OTOMASYON: Zabbix alarmı ({event_id}) aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: Ticket {ticket_id} re-opened."
        })
    else:
        log(f"❌ HATA: Ticket {ticket_id} açılamadı.")

def process_single_problem(problem):
    """Tek bir Zabbix problemini alır ve SC'de kontrol eder (İşçi Fonksiyonu)"""
    eid = problem.get('eventid')
    # name = problem.get('name')
    
    found_data = find_ticket_by_event_id(eid)
    
    tickets = []
    if isinstance(found_data, list): tickets = found_data
    elif isinstance(found_data, dict): tickets = [found_data]
    
    if not tickets:
        return
        
    for t in tickets:
        t_id = t.get('Id') or t.get('TicketId')
        status_id = t.get('StatusId')
        
        # Ticket KAPALI (2) ama Zabbix AKTİF
        if status_id in SC_STATUS_CLOSED_IDS:
            log(f"⚠️ UYUŞMAZLIK BULUNDU: Ticket {t_id} Kapalı / Zabbix Aktif.")
            reopen_ticket(t_id, eid)

# ================= MAIN =================

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URL eksik.")
        exit(1)

    log("--- Zabbix Sync (Turbo Mod) Başlatılıyor ---")
    
    active_problems = get_active_zabbix_problems()
    total_probs = len(active_problems)
    
    if total_probs == 0:
        log("Zabbix'te aktif problem yok.")
    else:
        log(f"İşlenecek Aktif Alarm Sayısı: {total_probs}")
        log(f"Paralel İşlem Başlıyor ({MAX_WORKERS} kanal)...")
        
        # --- PARALEL İŞLEME MOTORU ---
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Tüm problemleri havuza at ve dağıt
            futures = {executor.submit(process_single_problem, p): p for p in active_problems}
            
            # Tamamlananları bekle (Log akışı için)
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    log(f"Bir işlem hatası oluştu: {exc}")
        
    log("--- İşlem Tamamlandı ---")
