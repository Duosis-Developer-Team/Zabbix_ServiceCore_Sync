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

# ID Ayarları
# Senin kapalı ticket statü ID'nin 2 olduğunu teyit etmiştik.
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]

# Zabbix Event ID'sinin saklandığı alanın ID'si (Zabbix kodundan doğrulandı: 62128)
SC_CUSTOM_FIELD_EVENT_ID = int(os.getenv("SC_EVENT_ID_FIELD_ID", "62128"))

# Ticket açıldığında hangi statüye gelsin? (Varsayılan 1=New, eğer farklıysa AWX'ten değiştir)
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))

# Geriye dönük kaç dakika baksın?
LOOKBACK_MINUTES = int(os.getenv("LOOKBACK_MINUTES", "60"))

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def sc_req(method, endpoint, data=None):
    headers = {
        'Content-Type': 'application/json',
        'ApiKey': SC_API_TOKEN
    }
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data)
        else:
            r = requests.post(url, headers=headers, json=data) if method == 'POST' else requests.put(url, headers=headers, json=data)
        
        # HTML hatası veya 404 dönerse JSON decode patlar
        if r.status_code not in [200, 201]:
            log(f"API HTTP Error ({endpoint}): Status {r.status_code}")
            return {}
            
        return r.json()
    except Exception as e:
        log(f"API Exception ({endpoint}): {str(e)}")
        return {}

def zbx_req(method, params):
    # Zabbix JSON-RPC
    payload = {
        "jsonrpc": "2.0",
        "method": method,
        "params": params,
        "auth": ZBX_API_TOKEN,
        "id": 1
    }
    try:
        r = requests.post(ZBX_API_URL, json=payload)
        return r.json().get('result')
    except Exception as e:
        log(f"Zabbix API Error: {str(e)}")
        return None

# ================= MAIN LOGIC =================

def get_recently_closed_tickets():
    log(f"Searching tickets with Status IDs: {SC_STATUS_CLOSED_IDS}")

    # Search Endpoint Payload (ServiceCore yapısına uygun)
    payload = {
        "PageNumber": 1,
        "PageSize": 20,
        "TicketStatusIds": SC_STATUS_CLOSED_IDS
    }
    
    res = sc_req('POST', 'Incident/Search', payload)
    
    # API cevabı bazen {Data: [], ...} bazen direkt [] dönebilir, kontrol edelim.
    if not res:
        log("Search API returned empty response.")
        return []
        
    if isinstance(res, dict) and not res.get('IsSuccessfull', True):
        log(f"Search API returned IsSuccessfull=False: {res.get('Message')}")
        return []

    # Veriyi al
    tickets = res.get('Data', []) if isinstance(res, dict) else res
    
    if not tickets:
        log("No closed tickets found in the current page.")
        return []

    log(f"Found {len(tickets)} closed tickets. Checking details for Zabbix Event IDs...")
    
    candidates = []
    
    for t in tickets:
        t_id = t.get('Id') or t.get('TicketId')
        
        # Listede CustomField'lar eksik olabilir. Her ticket için detay çekiyoruz.
        # Bu işlem biraz yavaş olabilir ama en garanti yoldur.
        detail_res = sc_req('GET', f'Incident/GetById/{t_id}')
        
        if not detail_res or (isinstance(detail_res, dict) and not detail_res.get('IsSuccessfull')):
            continue

        # Gerçek detay verisi
        full_ticket = detail_res.get('Data', detail_res)
        
        # Zabbix Event ID'yi ara (Field ID: 62128)
        event_id = None
        c_vals = full_ticket.get('CustomFieldTicketIncidentValues', [])
        
        for cf in c_vals:
            if cf.get('FieldIncidentValueFieldId') == SC_CUSTOM_FIELD_EVENT_ID:
                val = cf.get('FieldIncidentValue')
                if val and str(val).isdigit(): # Sadece sayısal değerleri al
                    event_id = str(val)
                    break
        
        if event_id:
            # log(f"Candidate: Ticket {t_id} -> Event {event_id}")
            candidates.append({"id": t_id, "event_id": event_id})
            
    return candidates

def check_zabbix_problem_status(event_id):
    # 'recent': False -> Sadece şu an aktif problem tablosunda olanları getirir
    # (Resolved olanlar problem tablosundan silinip history'e geçer)
    res = zbx_req("problem.get", {
        "eventids": [event_id],
        "output": ["eventid"],
        "recent": False 
    })
    return (res and len(res) > 0)

def reopen_ticket(ticket_id, event_id):
    # Sadece statüyü değiştiriyoruz. Ekip (Group), Teknisyen (Agent) vs. değişmez.
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id,
        "statusId": SC_STATUS_REOPEN_ID,
        "closeReasonId": None
    })
    
    if res.get('IsSuccessfull'):
        log(f"ACTION: Ticket {ticket_id} RE-OPENED successfully.")
        
        # ServiceCore'a not düş
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": "OTOMASYON: Zabbix alarmı hala aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, 
            "noteType": 1
        })
        
        # Zabbix'e log düş (Action 4 = Add Message)
        zbx_req("event.acknowledge", {
            "eventids": [event_id], 
            "action": 4, 
            "message": f"AWX Automation: ServiceCore Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"ERROR: Failed to reopen ticket {ticket_id}. Msg: {res.get('Message')}")

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URLs missing. Check AWX Credentials.")
        exit(1)

    log("--- Starting Sync Check ---")
    
    try:
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
                    # Sorun yok, gerçekten kapanmış.
                    pass
                    
    except Exception as e:
        log(f"FATAL ERROR: {str(e)}")
            
    log("--- Completed ---")
