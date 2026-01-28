import os
import json
import requests
import urllib3
import socket
import re
import time
import concurrent.futures
from datetime import datetime

# 1. SSL Uyarılarını Sustur
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ================= CONFIG =================
SC_API_URL = os.getenv("SC_API_URL", "").rstrip('/')
SC_API_TOKEN = os.getenv("SC_API_TOKEN")
ZBX_API_URL = os.getenv("ZBX_API_URL") 
ZBX_API_TOKEN = os.getenv("ZBX_API_TOKEN")
SC_PANEL_URL = "https://operationsupport.bulutistan.com"

ZBX_DOMAIN = "watchman.bulutistan.com"
ZBX_REAL_IP = "10.6.116.178"

# --- AYARLAR ---
# Yasaklı Statüler (Kapalı, Çözüldü vb.)
bad_ids_str = os.getenv("SC_BAD_STATUS_IDS", "2, 46, 83, 94, 65")
SC_BAD_STATUS_IDS = [int(x.strip()) for x in bad_ids_str.split(',') if x.strip()]

# ================= DNS OVERRIDE =================
prv_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args):
    if args[0] == ZBX_DOMAIN:
        return prv_getaddrinfo(ZBX_REAL_IP, *args[1:])
    return prv_getaddrinfo(*args)
socket.getaddrinfo = new_getaddrinfo

# ================= HELPERS =================
def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}
    try:
        r = requests.post(ZBX_API_URL, json=payload, timeout=10, verify=False)
        return r.json().get('result')
    except: return None

def sc_req(method, endpoint, data=None):
    headers = {'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}
    url = f"{SC_API_URL}/api/v1/{endpoint}"
    try:
        if method == 'GET':
            r = requests.get(url, headers=headers, params=data, timeout=10, verify=False)
        else:
            r = requests.post(url, headers=headers, json=data, timeout=10, verify=False) if method == 'POST' else requests.put(url, headers=headers, json=data, timeout=10, verify=False)
        return r
    except: return None

# ================= CORE LOGIC =================

def get_active_problems_with_ticket_ids():
    log("Zabbix'ten aktif problemler çekiliyor...")
    
    params = {
        "output": ["eventid", "name", "acknowledged"],
        "selectAcknowledges": "extend",
        "recent": False,
        "sortfield": ["eventid"],
        "sortorder": "DESC",
        "limit": 1000
    }
    
    problems = zbx_req("problem.get", params)
    if not problems: return []
    
    targets = []
    
    for p in problems:
        event_id = p.get('eventid')
        is_acked = p.get('acknowledged')
        acks = p.get('acknowledges', [])
        
        if str(is_acked) == "1":
            continue
            
        ticket_id = None
        for ack in acks:
            msg = ack.get('message', '')
            match = re.search(r'ServiceCoreID\s*=\s*(\d+)', msg, re.IGNORECASE)
            if match:
                ticket_id = match.group(1)
                break
        
        if ticket_id:
            targets.append({"event_id": event_id, "ticket_id": ticket_id})
            
    return targets

def force_update_ticket(ticket_data, target_status):
    """
    Mevcut verileri koruyarak sadece Statü'yü günceller.
    """
    ticket_id = ticket_data.get('Id')
    
    # Mevcut Agent'ı Koru (Yoksa 0 gider)
    current_agent = ticket_data.get('AgentId')
    
    payload = {
        "ticketId": ticket_id,
        "statusId": target_status,
        "state": 1, # Her iki durumda da State 1 (Açık) uygundur
        "agentId": current_agent, # MEVCUT AGENT KORUNUR
        
        # Diğer zorunlu alanlar
        "ticketSubject": ticket_data.get('Subject') or ticket_data.get('TicketSubject'),
        "description": ticket_data.get('TicketDescription'),
        "orgUserId": ticket_data.get('OrgUserId'),
        "agentGroupId": ticket_data.get('AgentGroupId'),
        "priorityId": ticket_data.get('PriorityId'),
        "guid": ticket_data.get('Guid'),
        "isActive": True
    }
    
    res = sc_req('PUT', 'Incident/Update', payload)
    
    if not res or res.status_code == 405: 
         res = sc_req('POST', 'Incident/Update', payload)
         
    return res

def check_and_rescue_ticket(target):
    t_id = target['ticket_id']
    e_id = target['event_id']
    
    res = sc_req('GET', f'Incident/GetById/{t_id}')
    
    if res and res.status_code == 200:
        try:
            data = res.json().get('Data', {})
            current_status = data.get('StatusId')
            
            # Eğer statü yasaklı listedeyse (Kapalı, Çözüldü vb.)
            if current_status in SC_BAD_STATUS_IDS:
                
                # --- AKILLI STATÜ SEÇİMİ ---
                current_agent = data.get('AgentId')
                
                # Eğer Ticket'ın bir sahibi varsa -> 78 (Atandı) yap.
                if current_agent and current_agent > 0:
                    target_status = 78
                    log_msg = f"Ticket {t_id} (Agent: {current_agent}) -> Hedef: 78 (Atandı)"
                else:
                    # Eğer Ticket sahipsizse -> 1 (Üzerinde Çalışılıyor) yap.
                    # Çünkü sahipsiz ticket "Atandı" olamaz.
                    target_status = 1
                    log_msg = f"Ticket {t_id} (Sahipsiz) -> Hedef: 1 (Üzerinde Çalışılıyor)"
                
                log(f"⚠️ MÜDAHALE: {log_msg}")
                
                # Güncelleme Yap
                reopen_res = force_update_ticket(data, target_status)
                
                success = False
                if reopen_res:
                    try:
                        rj = reopen_res.json()
                        if rj.get('IsSuccessfull'):
                            success = True
                        else:
                            log(f"❌ Hata: {rj.get('Message')}")
                    except: pass

                if success:
                    log(f"✅ Başarılı. Yeni Statü: {target_status}")
                    
                    ticket_url = f"{SC_PANEL_URL}/Ticket/EditV2?id={t_id}"
                    
                    sc_req('POST', f'Incident/{t_id}/Conversations/Add', {
                        "description": "Zabbix alarmı aktif olduğu için otomasyon tarafından tekrardan açıldı.",
                        "isPrivate": True, "noteType": 1
                    })
                    
                    zbx_msg = f"AWX Automation: Ticket {t_id} re-opened. | URL={ticket_url}"
                    zbx_req("event.acknowledge", {
                        "eventids": [e_id], "action": 4, 
                        "message": zbx_msg
                    })
                    
        except Exception as e:
            log(f"Hata: {e}")
            pass

if __name__ == "__main__":
    if not SC_API_URL or not ZBX_API_URL:
        log("CRITICAL: API URL eksik.")
        exit(1)

    log(f"--- ServiceCore Smart Sync (Auto: 78 or 1) ---")
    
    targets = get_active_problems_with_ticket_ids()
    
    if not targets:
        log("Müdahale edilecek kayıt bulunamadı.")
    else:
        log(f"Kontrol edilecek eşleşme sayısı: {len(targets)}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            executor.map(check_and_rescue_ticket, targets)
            
    log("--- Bitti ---")
