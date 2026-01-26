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
ZBX_API_URL = os.getenv("ZBX_API_URL") # Domain olarak kalmalı
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# --- DNS HACK AYARLARI ---
ZBX_DOMAIN = "watchman.bulutistan.com"
ZBX_REAL_IP = "10.6.116.178"

# ServiceCore Ayarları
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))
SC_EVENT_FIELD_ID = str(os.getenv("SC_EVENT_ID_FIELD_ID", "62128")) # Senin ID

# TARAMA AYARLARI
START_ID = int(os.getenv("SC_START_ID", "146600")) # Buradan başlar, yukarı tırmanır
LOOKBACK_COUNT = 200 # En son kapatılan 200 ticketı kontrol et (Yeterli mi?)
MAX_WORKERS = 20 # Hız (Aynı anda 20 ticket)

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
        r = requests.post(ZBX_API_URL, json=payload, timeout=5, verify=False)
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

# ================= YENİ ID OKUMA MANTIĞI =================
def extract_event_id(ticket_data):
    """
    Ticket verisi içinden Event ID'yi bulmak için her deliğe bakar.
    """
    # 1. Yöntem: Standart Custom Fields (Eski yöntem)
    c_vals = ticket_data.get('CustomFieldTicketIncidentValues', [])
    for cf in c_vals:
        if str(cf.get('FieldIncidentValueFieldId')) == SC_EVENT_FIELD_ID:
            val = cf.get('FieldIncidentValue')
            if val and str(val).isdigit(): return str(val)

    # 2. Yöntem: 'CustomFields' Listesi (YENİ KEŞİF!)
    # Data['CustomFields'][0]['FieldValue'] yapısına bakıyoruz.
    cf_list = ticket_data.get('CustomFields', [])
    for item in cf_list:
        # Bu objenin içinde FieldValue var mı?
        val = item.get('FieldValue')
        # Ayrıca ID kontrolü yapalım (CustomFieldId veya FieldId olabilir)
        fid = item.get('CustomFieldId') or item.get('FieldId')
        
        # Eğer ID eşleşiyorsa AL
        if fid and str(fid) == SC_EVENT_FIELD_ID:
            return str(val)
            
        # ID bulamazsak ama değer Event ID'ye benziyorsa (10+ haneli sayı) ve isim tutuyorsa?
        # Şimdilik sadece değere bakalım, ID tutmasa bile uzun sayıysa adaydır.
        if val and str(val).isdigit() and len(str(val)) > 8:
            # İçinde Zabbix geçen bir alan mı diye bakılabilir ama risk almayalım,
            # direkt ID eşleşmesine güvenelim. Eğer ID yoksa bu yöntemi pas geçelim.
            pass

        # Ayrıca bu item'ın içinde de CustomFieldTicketIncidentValues olabilir (Loglarda gördük)
        nested_vals = item.get('CustomFieldTicketIncidentValues', [])
        for nv in nested_vals:
            if str(nv.get('FieldIncidentValueFieldId')) == SC_EVENT_FIELD_ID:
                return str(nv.get('FieldIncidentValue'))

    return None

def check_zabbix_problem_status(event_id):
    # recent=False: Sadece aktifler
    res = zbx_req("problem.get", {"eventids": [event_id], "output": ["eventid"], "recent": False})
    return (res and len(res) > 0)

def reopen_ticket(ticket_id, event_id):
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id, "statusId": SC_STATUS_REOPEN_ID, "closeReasonId": None
    })
    
    if res and res.json().get('IsSuccessfull'):
        log(f"✅ ACTION: Ticket {ticket_id} RE-OPENED (Event: {event_id})")
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": f"OTOMASYON: Zabbix alarmı ({event_id}) hala aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"❌ ERROR: Ticket {ticket_id} açılamadı.")

def process_ticket(ticket_id):
    # Ticket detayını çek
    res = sc_req('GET', f'Incident/GetById/{ticket_id}')
    if not res or res.status_code != 200: return
    
    try:
        j = res.json()
        if not j.get('IsSuccessfull'): return
        data = j.get('Data', {})
        
        # Sadece KAPALI olanlara bak
        status_id = data.get('StatusId')
        if status_id not in SC_STATUS_CLOSED_IDS:
            return # Açık ticketla işimiz yok

        # Event ID'yi ara (Yeni yöntemle)
        event_id = extract_event_id(data)
        
        if event_id:
            # Zabbix kontrolü
            if check_zabbix_problem_status(event_id):
                log(f"⚠️ UYUŞMAZLIK: Ticket {ticket_id} Kapalı <-> Zabbix Aktif ({event_id})")
                reopen_ticket(ticket_id, event_id)
                
    except Exception as e:
        pass

# ================= MAIN =================

def find_latest_id(start_from):
    curr = start_from
    step = 50
    log(f"En son Ticket ID bulunuyor (Başlangıç: {curr})...")
    
    # Hızlı tırmanış
    while True:
        res = sc_req('GET', f'Incident/GetById/{curr + step}')
        if res and res.status_code == 200 and res.json().get('IsSuccessfull'):
            curr += step
        else:
            break
            
    # Son düzlük
    for i in range(curr + 1, curr + step + 1):
        res = sc_req('GET', f'Incident/GetById/{i}')
        if not (res and res.status_code == 200 and res.json().get('IsSuccessfull')):
            return i - 1
            
    return curr

if __name__ == "__main__":
    log("--- ServiceCore -> Zabbix Sync (Scanner Mode) ---")
    
    # 1. En son ID'yi bul
    latest_id = find_latest_id(START_ID)
    log(f"En güncel Ticket ID: {latest_id}")
    
    # 2. Geriye doğru tara (Multi-Thread)
    end_id = max(1, latest_id - LOOKBACK_COUNT)
    id_list = list(range(latest_id, end_id, -1))
    
    log(f"Son {len(id_list)} ticket taranıyor ({latest_id} -> {end_id})...")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        executor.map(process_ticket, id_list)
        
    log("--- Tamamlandı ---")
