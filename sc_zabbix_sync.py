import os
import json
import requests
import urllib3
import socket
import time
from datetime import datetime

# 1. SSL Uyarılarını Sustur
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIG =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL") # Buraya DOMAIN gelmeli (Credential'dan)
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")

# --- KRİTİK AYAR: DNS OVERRIDE ---
# AWX DNS çözemediği için, Domain'i IP'ye biz yönlendiriyoruz.
ZBX_DOMAIN = "watchman.bulutistan.com"
ZBX_REAL_IP = "10.6.116.178"  # Sizin verdiğiniz IP

# ServiceCore Ayarları
closed_ids_str = os.getenv("SC_CLOSED_STATUS_IDS", "2")
SC_STATUS_CLOSED_IDS = [int(x.strip()) for x in closed_ids_str.split(',') if x.strip()]
SC_STATUS_REOPEN_ID = int(os.getenv("SC_REOPEN_STATUS_ID", "1"))
SC_FIELD_KEY = os.getenv("SC_FIELD_KEY", "Eventid") 

# ================= DNS HACK (The Magic) =================
# Bu blok, Python'un socket kütüphanesini 'hook'lar.
# Kod ne zaman 'watchman.bulutistan.com'a gitmeye çalışsa, 
# DNS sunucusuna sormadan direkt bizim verdiğimiz IP'ye gider.
# Böylece URL'de Domain kaldığı için SSL (SNI) hatası almayız!

prv_getaddrinfo = socket.getaddrinfo

def new_getaddrinfo(*args):
    # Eğer sorgulanan adres bizim Zabbix domaini ise
    if args[0] == ZBX_DOMAIN:
        # Direkt IP'yi döndür (Port ve protokolü koruyarak)
        return prv_getaddrinfo(ZBX_REAL_IP, *args[1:])
    return prv_getaddrinfo(*args)

socket.getaddrinfo = new_getaddrinfo
# ========================================================

def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    # URL içinde Domain yazıyor ama Python arka planda IP'ye gidecek
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
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

# ================= CORE LOGIC =================

def get_active_zabbix_problems():
    log(f"Fetching active problems from Zabbix ({ZBX_DOMAIN})...")
    params = {
        "output": ["eventid", "name"],
        "recent": False,
        "sortfield": ["eventid"],
        "sortorder": "DESC"
    }
    problems = zbx_req("problem.get", params)
    
    if problems is None:
        log("Could not fetch problems from Zabbix. Check Network/Credentials.")
        return []
    return problems

def find_ticket_by_event_id(event_id):
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
        except: pass
    return None

def reopen_ticket(ticket_id, event_id):
    res = sc_req('PUT', 'Incident/UpdateTicketStatus', {
        "ticketId": ticket_id, "statusId": SC_STATUS_REOPEN_ID, "closeReasonId": None
    })
    if res and res.json().get('IsSuccessfull'):
        log(f"✅ ACTION: Ticket {ticket_id} RE-OPENED.")
        sc_req('POST', f'Incident/{ticket_id}/Conversations/Add', {
            "description": f"OTOMASYON: Zabbix alarmı (Event: {event_id}) aktif olduğu için ticket tekrar açıldı.",
            "isPrivate": True, "noteType": 1
        })
        zbx_req("event.acknowledge", {
            "eventids": [event_id], "action": 4, 
            "message": f"AWX Automation: ServiceCore Ticket {ticket_id} re-opened because alarm is still active."
        })
    else:
        log(f"❌ ERROR: Failed to reopen ticket {ticket_id}")

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URLs missing.")
        exit(1)

    log("--- Starting Zabbix-Driven Sync (DNS Hack Enabled) ---")
    
    active_problems = get_active_zabbix_problems()
    
    if not active_problems:
        log("No active problems found (or connection failed).")
    else:
        log(f"Found {len(active_problems)} active problems in Zabbix.")
        
        for problem in active_problems:
            eid = problem.get('eventid')
            name = problem.get('name')
            
            found_data = find_ticket_by_event_id(eid)
            
            tickets = []
            if isinstance(found_data, list): tickets = found_data
            elif isinstance(found_data, dict): tickets = [found_data]
            
            if not tickets: continue
                
            for t in tickets:
                t_id = t.get('Id') or t.get('TicketId')
                status_id = t.get('StatusId')
                
                if status_id in SC_STATUS_CLOSED_IDS:
                    log(f"⚠️ MISMATCH: Zabbix Active ({eid}) <-> Ticket Closed ({t_id}). Status: {status_id}")
                    reopen_ticket(t_id, eid)

    log("--- Completed ---")
