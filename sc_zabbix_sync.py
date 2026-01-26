import os
import json
import requests
import time
from datetime import datetime, timedelta

# ================= CONFIG (Environment Variables) =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL")
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# Statü ve ID Ayarları
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]

SC_CUSTOM_FIELD_EVENT_ID = int(os.getenv("SC_EVENT_ID_FIELD_ID", "62128"))
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))

# Başlangıç ID'si (Opsiyonel - Vermezsen otomatik bulur)
START_ID = int(os.getenv("SC_START_ID", "146600"))

# KAÇ GÜN GERİYE BAKSIN? (AWX'ten 'LOOKBACK_DAYS' olarak verebilirsin. Varsayılan 7 gün)
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "7")) 

# Güvenlik Limiti: Sonsuz döngüye girmesin diye maksimum kaç ticket tarasın?
MAX_REQUEST_LIMIT = 3000

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data)
        else:
            r = requests.post(url, headers=headers, json=data) if method == 'POST' else requests.put(url, headers=headers, json=data)
        return r
    except:
        return None

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        r = requests.post(ZBX_API_URL, json=payload)
        return r.json().get('result')
    except:
        return None

def parse_sc_date(date_str):
    # Örn: "2026-01-26T15:06:22.58" -> datetime objesi
    try:
        # Milisaniyeyi atalım, karmaşa çıkmasın
        clean_date = date_str.split('.')[0]
        return datetime.strptime(clean_date, "%Y-%m-%dT%H:%M:%S")
    except:
        return None

# ================= SMART LOGIC =================

def find_latest_ticket_id(start_from):
    """En son Ticket ID'yi bulmak için yukarı tırmanır"""
    current = start_from
    step = 10
    log(f"Finding latest ticket ID starting from {current}...")
    
    # 1. Hızlı Tırmanış
    while True:
        next_val = current + step
        res = sc_req('GET', f'Incident/GetById/{next_val}')
        if res and res.status_code == 200:
            try:
                if res.json().get('IsSuccessfull'):
                    current = next_val
                    continue
            except: pass
        break
    
    # 2. Hassas Tırmanış
    for i in range(current + 1, current + step + 1):
        res = sc_req('GET', f'Incident/GetById/{i}')
        if res and res.status_code == 200:
             try:
                if res.json().get('IsSuccessfull'): current = i
                else: break
             except: break
        else: break
            
    log(f"Latest Ticket ID found: {current}")
    return current

def scan_tickets_by_date(latest_id, days_limit):
    candidates = []
    
    # Bugünden X gün öncesi (Limit Tarihi)
    limit_date = datetime.now() - timedelta(days=days_limit)
    log(f"Scanning tickets backwards until date: {limit_date.strftime('%Y-%m-%d %H:%M')}")
    
    current_id = latest_id
    checked_count = 0
    
    while checked_count < MAX_REQUEST_LIMIT:
        # API'yi yormamak için çok hafif bekleme
        # time.sleep(0.02) 
        
        res = sc_req('GET', f'Incident/GetById/{current_id}')
        
        if res and res.status_code == 200:
            try:
                j = res.json()
                if j.get('IsSuccessfull'):
                    data = j.get('Data', {})
                    
                    # 1. TARİH KONTROLÜ (En Kritik Yer)
                    # CreatedDate veya AssigntmentDate kullanılabilir.
                    t_date_str = data.get('CreatedDate') 
                    if t_date_str:
                        t_date = parse_sc_date(t_date_str)
                        if t_date and t_date < limit_date:
                            log(f"Reached time limit at Ticket {current_id} ({t_date_str}). Stopping scan.")
                            break
                    
                    # 2. STATÜ ve ZABBIX ID KONTROLÜ
                    status_id = data.get('StatusId')
                    if status_id in SC_STATUS_CLOSED_IDS:
                        c_vals = data.get('CustomFieldTicketIncidentValues', [])
                        for cf in c_vals:
                            if cf.get('FieldIncidentValueFieldId') == SC_CUSTOM_FIELD_EVENT_ID:
                                val = cf.get('FieldIncidentValue')
                                if val and str(val).isdigit():
                                    candidates.append({"id": current_id, "event_id": str(val)})
                                    break
            except:
                pass
        
        current_id -= 1
        checked_count += 1
        
        if current_id <= 0:
            break
            
    if checked_count >= MAX_REQUEST_LIMIT:
        log(f"WARNING: Reached safety request limit ({MAX_REQUEST_LIMIT}) before hitting date limit.")
        
    return candidates

def check_zabbix_problem_status(event_id):
    res = zbx_req("problem.get", {"eventids": [event_id], "output": ["eventid"], "recent": False})
    return (res and len(res) > 0)

def reopen_ticket(ticket_id, event_id):
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id, "statusId": SC_STATUS_REOPEN_ID, "closeReasonId": None
    })
    
    if res and res.json().get('IsSuccessfull'):
        log(f"ACTION: Ticket {ticket_id} RE-OPENED.")
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": "OTOMASYON: Zabbix alarmı hala aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: ServiceCore Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"ERROR: Failed to reopen ticket {ticket_id}")

if __name__ == "__main__":
    if not SC_API_URL:
        log("CRITICAL: API URLs missing.")
        exit(1)

    log("--- Starting Date-Based Sync Check ---")
    
    # 1. En güncel ID'yi bul
    latest = find_latest_ticket_id(START_ID)
    
    # 2. Tarih limitine kadar geriye tara
    candidates = scan_tickets_by_date(latest, LOOKBACK_DAYS)
    
    if not candidates:
        log(f"No relevant closed tickets found in the last {LOOKBACK_DAYS} days.")
    else:
        log(f"Found {len(candidates)} candidates in the last {LOOKBACK_DAYS} days. Checking Zabbix...")
        
        for cand in candidates:
            if check_zabbix_problem_status(cand['event_id']):
                log(f"MISMATCH: Ticket {cand['id']} Closed / Zabbix Active. Reopening...")
                reopen_ticket(cand['id'], cand['event_id'])
    
    log("--- Completed ---")
