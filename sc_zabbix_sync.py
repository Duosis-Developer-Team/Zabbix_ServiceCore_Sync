import os
import json
import requests
import urllib3
import time
from datetime import datetime

# 1. SSL Uyarılarını Sustur (IP ile gidince hata vermemesi için Kritik!)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIG (Environment Variables) =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL")
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# ServiceCore Statüleri
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))

# Custom Field Key (Eventid)
SC_FIELD_KEY = os.getenv("SC_FIELD_KEY", "Eventid") 

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        # verify=False: SSL sertifikasını kontrol etme (IP kullanınca şart)
        r = requests.post(ZBX_API_URL, json=payload, timeout=10, verify=False)
        return r.json().get('result')
    except Exception as e:
        log(f"Zabbix Error: {e}")
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
        log(f"SC Error: {e}")
        return None

# ================= CORE LOGIC (REVERSE SYNC) =================

def get_active_zabbix_problems():
    """Zabbix'teki aktif problemleri çeker"""
    log("Fetching active problems from Zabbix...")
    # recent: False -> Sadece şu an problem tablosunda olanlar (Çözülmemişler)
    params = {
        "output": ["eventid", "name"],
        "recent": False,
        "sortfield": ["eventid"],
        "sortorder": "DESC"
    }
    problems = zbx_req("problem.get", params)
    
    if problems is None:
        log("Could not fetch problems from Zabbix. Check URL/Network.")
        return []
    return problems

def find_ticket_by_event_id(event_id):
    """Event ID ile ticket arar"""
    payload = {
        "fieldKey": SC_FIELD_KEY,
        "fieldValue": str(event_id),
        "isAddUtcHours": False,
        "addUtcHours": 0,
        "minusSecondValue": 0,
        "dataKey": ""
    }
    
    res = sc_req('POST', 'Incident/SearchIncidentByCustomField', payload)
    
    if res and res.status_code == 200:
        try:
            j = res.json()
            if j.get('IsSuccessfull'):
                return j.get('Data')
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
        
        # Not düş
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": "OTOMASYON: Zabbix alarmı (Event: "+str(event_id)+") hala aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        
        # Zabbix'e Ack bas
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: ServiceCore Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"❌ ERROR: Failed to reopen ticket {ticket_id}")

# ================= MAIN =================

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URLs missing.")
        exit(1)

    log("--- Starting Zabbix-Driven Sync (Reverse Logic) ---")
    
    active_problems = get_active_zabbix_problems()
    
    if not active_problems:
        log("No active problems found (or connection failed).")
    else:
        log(f"Found {len(active_problems)} active problems in Zabbix.")
        
        for problem in active_problems:
            eid = problem.get('eventid')
            name = problem.get('name')
            
            # Bu Event ID'ye sahip bir ticket var mı?
            found_data = find_ticket_by_event_id(eid)
            
            tickets = []
            if isinstance(found_data, list):
                tickets = found_data
            elif isinstance(found_data, dict):
                tickets = [found_data]
            
            if not tickets:
                continue
                
            for t in tickets:
                t_id = t.get('Id') or t.get('TicketId')
                status_id = t.get('StatusId')
                
                # Ticket KAPALI (2) ama Zabbix AKTİF ise -> AÇ
                if status_id in SC_STATUS_CLOSED_IDS:
                    log(f"⚠️ MISMATCH: Zabbix Active ({eid}) <-> Ticket Closed ({t_id}). Status: {status_id}")
                    reopen_ticket(t_id, eid)

    log("--- Completed ---")
