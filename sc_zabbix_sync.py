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

# ID Ayarları (Varsayılanları senin sistemine göre güncelledim)
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")  # <-- SENİN ID BURADA
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]

SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1")) # Open ID'si (Eğer farklıysa AWX'ten değiştir)
SC_CUSTOM_FIELD_EVENT_ID = int(os.getenv("SC_EVENT_ID_FIELD_ID", "62128"))
LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", "60"))

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
        
        # API bazen 200 döner ama IsSuccessfull false olabilir
        j = r.json()
        return j
    except Exception as e:
        log(f"API Error ({endpoint}): {str(e)}")
        return {}

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        r = requests.post(ZBX_API_URL, json=payload)
        return r.json().get('result')
    except Exception as e:
        log(f"Zabbix API Error: {str(e)}")
        return None

# ================= MAIN LOGIC =================
def get_recently_closed_tickets():
    # Tarih Hesaplama (UTC Timezone sorunu yaşamamak için geniş tutuyoruz)
    start_date = (datetime.now() - timedelta(minutes=LOOKBACK_MINUTES)).strftime("%Y-%m-%dT%H:%M:%S")
    
    log(f"Searching tickets closed after {start_date} with Status IDs: {SC_STATUS_CLOSED_IDS}")

    payload = {
        "PageNumber": 1,
        "PageSize": 20, # Performans için düşürdük
        "TicketStatusIds": SC_STATUS_CLOSED_IDS,
        # "UpdatedDateStart": start_date # API destekliyorsa açılabilir, şimdilik manuel filtreleyeceğiz
    }
    
    res = sc_req('POST', 'Incident/Search', payload)
    
    if not res.get('IsSuccessfull'):
        log(f"Search failed: {res.get('Message')}")
        return []

    tickets = res.get('Data', [])
    log(f"DEBUG: Search API returned {len(tickets)} raw tickets.")
    
    candidates = []
    
    for t in tickets:
        t_id = t.get('Id') or t.get('TicketId')
        
        # Custom Fieldlar Search listesinde gelmeyebilir. Kontrol edelim.
        c_fields = t.get('CustomFieldTicketIncidentValues', [])
        
        # Eğer liste boşsa veya custom field eksikse, mecburen DETAY (GetById) çekeceğiz.
        if not c_fields:
            # log(f"DEBUG: Fetching details for Ticket {t_id} (Missing fields in search)...")
            detail_res = sc_req('GET', f'Incident/GetById/{t_id}')
            if detail_res.get('IsSuccessfull'):
                t = detail_res.get('Data', {})
                c_fields = t.get('CustomFieldTicketIncidentValues', [])
            else:
                continue

        event_id = None
        for cf in c_fields:
            if cf.get('FieldIncidentValueFieldId') == SC_CUSTOM_FIELD_EVENT_ID:
                event_id = cf.get('FieldIncidentValue')
                break
        
        if event_id:
            # log(f"DEBUG: Candidate Found -> Ticket {t_id} has Event ID {event_id}")
            candidates.append({"id": t_id, "event_id": event_id})
        # else:
            # log(f"DEBUG: Ignored Ticket {t_id} (No Zabbix Event ID found)")
            
    return candidates

def check_zabbix_problem_status(event_id):
    # recent: False -> Sadece şu an problem tablosunda olanları getirir
    res = zbx_req("problem.get", {"eventids": [event_id], "output": ["eventid"], "recent": False})
    return (res and len(res) > 0)

def reopen_ticket(ticket_id, event_id):
    # DİKKAT: Reopen ID'sini 1 olarak varsaydık. Senin sistemde farklıysa AWX'ten sc_reopen_id değiştir.
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id,
        "statusId": SC_STATUS_REOPEN_ID,
        "closeReasonId": None
    })
    
    if res.get('IsSuccessfull'):
        log(f"ACTION: Ticket {ticket_id} RE-OPENED successfully.")
        
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": "OTOMASYON: Zabbix alarmı hala aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: ServiceCore Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"ERROR: Failed to reopen ticket {ticket_id}. Msg: {res.get('Message')}")

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URLs missing.")
        exit(1)

    log("--- Starting Sync Check ---")
    
    candidates = get_recently_closed_tickets()
    
    if not candidates:
        log("No candidates found with Event IDs.")
    else:
        log(f"Checking {len(candidates)} closed tickets against Zabbix...")
        
        for cand in candidates:
            if check_zabbix_problem_status(cand['event_id']):
                log(f"MISMATCH DETECTED: Ticket {cand['id']} is Closed but Zabbix Event {cand['event_id']} is ACTIVE.")
                reopen_ticket(cand['id'], cand['event_id'])
            else:
                # log(f"OK: Ticket {cand['id']} matches Zabbix status (Resolved).")
                pass
            
    log("--- Completed ---")
