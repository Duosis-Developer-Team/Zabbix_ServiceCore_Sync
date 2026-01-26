import os
import json
import requests
import time
from datetime import datetime, timedelta

# ================= CONFIG (Environment Variables) =================
# Bu değerler AWX tarafından gönderilecek
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL")
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# ID ve Ayarlar (Varsayılan değerler string olarak alınır, integera çevrilir)
# Örn: "5,6" şeklinde gelirse listeye çeviririz
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "5,6") 
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]

SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))
SC_CUSTOM_FIELD_EVENT_ID = int(os.getenv("SC_EVENT_ID_FIELD_ID", "62128"))
LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", "60"))

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    if method == 'GET':
        r = requests.get(url, headers=headers, params=data)
    else:
        r = requests.post(url, headers=headers, json=data) if method == 'POST' else requests.put(url, headers=headers, json=data)
    try: return r.json()
    except: return {}

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    r = requests.post(ZBX_API_URL, json=payload)
    try: return r.json().get('result')
    except: return None

# ================= MAIN LOGIC =================
def get_recently_closed_tickets():
    payload = {
        "PageNumber": 1, "PageSize": 50,
        "TicketStatusIds": SC_STATUS_CLOSED_IDS,
    }
    res = sc_req('POST', 'Incident/Search', payload)
    tickets = res.get('Data', []) if res else []
    
    candidates = []
    for t in tickets:
        event_id = None
        # Custom fieldları tara
        c_fields = t.get('CustomFieldTicketIncidentValues', [])
        for cf in c_fields:
            if cf.get('FieldIncidentValueFieldId') == SC_CUSTOM_FIELD_EVENT_ID:
                event_id = cf.get('FieldIncidentValue')
                break
        
        if event_id:
            candidates.append({"id": t.get('Id'), "event_id": event_id})
    return candidates

def check_zabbix_problem_status(event_id):
    # 'recent': False -> Sadece şu an aktif olan problemleri getirir
    res = zbx_req("problem.get", {"eventids": [event_id], "output": ["eventid"], "recent": False})
    return (res and len(res) > 0)

def reopen_ticket(ticket_id, event_id):
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id,
        "statusId": SC_STATUS_REOPEN_ID,
        "closeReasonId": None
    })
    
    if res.get('IsSuccessfull'):
        log(f"Ticket {ticket_id} RE-OPENED.")
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": "OTOMASYON: Zabbix alarmı hala aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"Automation: Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"Failed to reopen ticket {ticket_id}. Msg: {res.get('Message')}")

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("HATA: API URL'leri tanımlanmamış. Environment Variable'ları kontrol edin.")
        exit(1)

    log("Starting Sync Check...")
    candidates = get_recently_closed_tickets()
    log(f"Found {len(candidates)} closed tickets with Event IDs.")
    
    for cand in candidates:
        if check_zabbix_problem_status(cand['event_id']):
            log(f"MISMATCH: Ticket {cand['id']} Closed / Zabbix Active. Reopening...")
            reopen_ticket(cand['id'], cand['event_id'])
            
    log("Completed.")