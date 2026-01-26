import os
import json
import requests
import time
import concurrent.futures
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

# Başlangıç ID (Opsiyonel)
START_ID = int(os.getenv("SC_START_ID", "146600"))

# Kaç gün geriye baksın?
LOOKBACK_DAYS = int(os.getenv("LOOKBACK_DAYS", "1")) 

# Thread Sayısı (Aynı anda kaç sorgu atılsın?)
MAX_WORKERS = 20  # 20 paralel istek idealdir, API'yi yormaz ama çok hızlandırır.
CHUNK_SIZE = 50   # Her seferde 50'li paketler halinde işle

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data, timeout=10)
        else:
            r = requests.post(url, headers=headers, json=data, timeout=10) if method == 'POST' else requests.put(url, headers=headers, json=data, timeout=10)
        return r
    except:
        return None

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        r = requests.post(ZBX_API_URL, json=payload, timeout=5)
        return r.json().get('result')
    except:
        return None

def parse_sc_date(date_str):
    try:
        clean_date = date_str.split('.')[0]
        return datetime.strptime(clean_date, "%Y-%m-%dT%H:%M:%S")
    except:
        return None

# ================= CORE LOGIC =================

def fetch_ticket_details(ticket_id):
    """Tek bir ticket'ın detayını çeker ve analiz eder"""
    res = sc_req('GET', f'Incident/GetById/{ticket_id}')
    
    if res and res.status_code == 200:
        try:
            j = res.json()
            if j.get('IsSuccessfull'):
                return j.get('Data', {})
        except:
            pass
    return None

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

# ================= FAST SCAN LOGIC =================

def find_latest_ticket_id(start_from):
    current = start_from
    step = 10
    log(f"Finding latest ticket ID starting from {current}...")
    
    # Hızlı tırmanış
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
        
    # Hassas tırmanış (Son noktayı bul)
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

def fast_scan_and_process(latest_id, days_limit):
    limit_date = datetime.now() - timedelta(days=days_limit)
    log(f"Parallel Scanning backwards until: {limit_date.strftime('%Y-%m-%d %H:%M')}")
    
    current_high = latest_id
    stop_scan = False
    processed_count = 0
    
    # Chunklar halinde işle (Örn: 146645'ten 146595'e kadar olan 50 ticketı al)
    while not stop_scan and processed_count < 5000: # Güvenlik limiti 5000
        
        # ID listesi oluştur
        current_low = max(1, current_high - CHUNK_SIZE)
        id_batch = list(range(current_high, current_low, -1))
        
        if not id_batch:
            break
            
        # log(f"Processing batch: {id_batch[0]} -> {id_batch[-1]}")
        
        # --- PARALEL İŞLEME BAŞLIYOR ---
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # ID'leri fonksiyona dağıt
            future_to_id = {executor.submit(fetch_ticket_details, tid): tid for tid in id_batch}
            
            for future in concurrent.futures.as_completed(future_to_id):
                tid = future_to_id[future]
                try:
                    data = future.result()
                    if not data:
                        continue # Ticket yok veya hata
                    
                    # 1. TARİH KONTROLÜ
                    t_date_str = data.get('CreatedDate')
                    if t_date_str:
                        t_date = parse_sc_date(t_date_str)
                        if t_date and t_date < limit_date:
                            # Bu batch'te eski tarihli ticket bulundu.
                            # Daha geriye gitmeye gerek yok (veya batch bitince dur)
                            stop_scan = True
                            # log(f"Time limit reached at {tid}")
                            continue

                    # 2. STATÜ ve ZABBIX KONTROLÜ
                    status_id = data.get('StatusId')
                    if status_id in SC_STATUS_CLOSED_IDS:
                        c_vals = data.get('CustomFieldTicketIncidentValues', [])
                        event_id = None
                        for cf in c_vals:
                            if cf.get('FieldIncidentValueFieldId') == SC_CUSTOM_FIELD_EVENT_ID:
                                val = cf.get('FieldIncidentValue')
                                if val and str(val).isdigit():
                                    event_id = str(val)
                                    break
                        
                        if event_id:
                            # Senkron çağrı (Zabbix kontrolü kritik olduğu için burada bekleyebiliriz)
                            # Zaten Zabbix kontrolü sadece aday ticketlarda yapılıyor, sayı az.
                            if check_zabbix_problem_status(event_id):
                                log(f"MISMATCH: Ticket {tid} Closed / Zabbix Active. Reopening...")
                                reopen_ticket(tid, event_id)
                                
                except Exception as exc:
                    pass
                    
        processed_count += len(id_batch)
        current_high = current_low
        
        if current_high <= 1:
            break

    return processed_count

if __name__ == "__main__":
    if not SC_API_URL:
        log("CRITICAL: API URLs missing.")
        exit(1)

    log("--- Starting High-Performance Sync Check ---")
    
    # 1. En son ID'yi bul
    latest = find_latest_ticket_id(START_ID)
    
    # 2. Paralel Tara ve İşle
    total = fast_scan_and_process(latest, LOOKBACK_DAYS)
    
    log(f"--- Completed (Scanned ~{total} ID slots) ---")
