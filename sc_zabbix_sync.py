import os
import json
import requests
import time
from datetime import datetime

# ================= CONFIG (Environment Variables) =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL")
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# ServiceCore Statüleri
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))

# Custom Field Key (Json çıktınızda "Eventid" olarak görünüyordu, buna dikkat!)
SC_FIELD_KEY = os.getenv("SC_FIELD_KEY", "Eventid") 

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        r = requests.post(ZBX_API_URL, json=payload, timeout=10)
        return r.json().get('result')
    except Exception as e:
        log(f"Zabbix Error: {e}")
        return None

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data, timeout=10)
        else:
            r = requests.post(url, headers=headers, json=data, timeout=10) if method == 'POST' else requests.put(url, headers=headers, json=data, timeout=10)
        return r
    except Exception as e:
        log(f"SC Error: {e}")
        return None

# ================= CORE LOGIC =================

def get_active_zabbix_problems():
    """Zabbix'teki aktif problemleri çeker"""
    log("Fetching active problems from Zabbix...")
    # recent: False -> Sadece şu an aktif olanlar
    # severity: Opsiyonel filtre eklenebilir
    params = {
        "output": ["eventid", "name"],
        "recent": False,
        "sortfield": ["eventid"],
        "sortorder": "DESC"
    }
    problems = zbx_req("problem.get", params)
    if not problems:
        return []
    return problems

def find_ticket_by_event_id(event_id):
    """Sizin bulduğunuz Endpoint ile ticket arar"""
    
    # DTO Yapısı
    payload = {
        "fieldKey": SC_FIELD_KEY,     # Json'da "Eventid" idi
        "fieldValue": str(event_id),
        "isAddUtcHours": False,
        "addUtcHours": 0,
        "minusSecondValue": 0,
        "dataKey": ""
    }
    
    # Endpoint: /api/v1/Incident/SearchIncidentByCustomField
    res = sc_req('POST', 'Incident/SearchIncidentByCustomField', payload)
    
    if res and res.status_code == 200:
        try:
            j = res.json()
            if j.get('IsSuccessfull'):
                return j.get('Data') # Ticket listesi dönebilir
        except:
            pass
    return None

def reopen_ticket(ticket_id, event_id):
    """Ticket'ı tekrar açar"""
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id, "statusId": SC_STATUS_REOPEN_ID, "closeReasonId": None
    })
    
    if res and res.json().get('IsSuccessfull'):
        log(f"✅ ACTION: Ticket {ticket_id} RE-OPENED.")
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": "OTOMASYON: Zabbix alarmı (Event: "+str(event_id)+") hala aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        # Zabbix'e de bilgi ver
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: ServiceCore Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"❌ ERROR: Failed to reopen ticket {ticket_id}")

# ================= MAIN =================

if __name__ == "__main__":
    if not SC_API_URL:
        log("CRITICAL: API URLs missing.")
        exit(1)

    log("--- Starting Zabbix-Driven Sync (Reverse Logic) ---")
    
    # 1. Zabbix'teki aktif problemleri al (Kaynak küçüldü -> Hızlandı)
    active_problems = get_active_zabbix_problems()
    log(f"Found {len(active_problems)} active problems in Zabbix.")
    
    for problem in active_problems:
        eid = problem.get('eventid')
        name = problem.get('name')
        
        # 2. Bu Event ID'ye sahip bir ticket var mı?
        found_data = find_ticket_by_event_id(eid)
        
        # found_data bazen liste, bazen obje dönebilir. Kontrol edelim.
        tickets = []
        if isinstance(found_data, list):
            tickets = found_data
        elif isinstance(found_data, dict):
            tickets = [found_data]
            
        if not tickets:
            # log(f"No ticket found for Event {eid} ({name}) - OK")
            continue
            
        # 3. Ticket bulundu, statüsünü kontrol et
        for t in tickets:
            t_id = t.get('Id') or t.get('TicketId')
            status_id = t.get('StatusId')
            
            # Eğer Status ID, kapalılar listesindeyse (2) -> HATA VAR!
            if status_id in SC_STATUS_CLOSED_IDS:
                log(f"⚠️ MISMATCH: Zabbix Active ({eid}) <-> Ticket Closed ({t_id}). Status: {status_id}")
                reopen_ticket(t_id, eid)
            else:
                # Ticket açık, sorun yok.
                pass

    log("--- Completed ---")
