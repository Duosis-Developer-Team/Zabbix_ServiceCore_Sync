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

# --- MÜDAHALE EDİLECEK STATÜLER ---
# 2: Kapalı, 83: Çözüldü, 94: İptal, 46: Tamamlanmış, 65: Ertelenen
bad_ids_str = os.getenv("SC_BAD_STATUS_IDS", "2, 83, 94, 46, 65")
SC_BAD_STATUS_IDS = [int(x.strip()) for x in bad_ids_str.split(',') if x.strip()]

# DNS Override
prv_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args):
    if args[0] == ZBX_DOMAIN: return prv_getaddrinfo(ZBX_REAL_IP, *args[1:])
    return prv_getaddrinfo(*args)
socket.getaddrinfo = new_getaddrinfo

# ================= HELPERS =================
def log(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    try:
        r = requests.post(ZBX_API_URL, json={"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}, timeout=15, verify=False)
        return r.json().get('result')
    except: return None

# ServiceCore İstek Yardımcıları
def sc_get(endpoint):
    try: return requests.get(f"{SC_API_URL}/api/v1/{endpoint}", headers={'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}, timeout=10, verify=False)
    except: return None

def sc_put(endpoint, data):
    try: return requests.put(f"{SC_API_URL}/api/v1/{endpoint}", headers={'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}, json=data, timeout=10, verify=False)
    except: return None

def sc_post(endpoint, data):
    try: return requests.post(f"{SC_API_URL}/api/v1/{endpoint}", headers={'Content-Type': 'application/json', 'ApiKey': SC_API_TOKEN}, json=data, timeout=10, verify=False)
    except: return None

# ================= CORE LOGIC =================

def get_active_problems_with_ticket_ids():
    # --- YENİ FİLTRE: SON 30 GÜN ---
    time_from = int(time.time()) - (30 * 24 * 60 * 60)
    
    log("Zabbix problemleri taranıyor (Son 30 gün, Notlu & Ack Olmayanlar)...")
    
    params = {
        "output": ["eventid", "name", "acknowledged"],
        "selectAcknowledges": "extend",
        "time_from": time_from,         # Limit yerine tarih kısıtı
        "sortfield": ["eventid"], 
        "sortorder": "DESC"
    }
    
    problems = zbx_req("problem.get", params)
    if not problems: return []
    
    targets = []
    for p in problems:
        # --- KURAL 1: EĞER PROBLEM ACKNOWLEDGE EDİLMİŞSE PAS GEÇ (HATA YOK) ---
        if str(p.get('acknowledged')) == "1":
            continue

        # --- KURAL 2: NOTLARI TARA VE ID BUL ---
        acks = p.get('acknowledges', [])
        if not acks:
            continue 
            
        for ack in acks:
            msg = ack.get('message', '')
            match = re.search(r'ServiceCoreID\s*=\s*(\d+)', msg, re.IGNORECASE)
            
            if match:
                targets.append({
                    "event_id": p.get('eventid'), 
                    "ticket_id": match.group(1)
                })
                break 
    return targets

def update_status(ticket_id, status_id):
    """Statü güncelleme işlemi"""
    res = sc_put('Incident/UpdateTicketStatus', {
        "ticketId": int(ticket_id), 
        "statusId": int(status_id), 
        "closeReasonId": None
    })
    if res and res.status_code == 200:
        rj = res.json()
        return rj.get('IsSuccessfull'), rj.get('Message')
    return False, "HTTP Error"

def check_and_enforce_workflow(target):
    t_id = target['ticket_id']
    e_id = target['event_id']
    
    # 1. Ticket Verisini Çek
    res = sc_get(f'Incident/GetById/{t_id}')
    
    if res and res.status_code == 200:
        try:
            data = res.json().get('Data', {})
            current_status = data.get('StatusId')
            agent_id = data.get('AgentId')
            
            # 2. Eğer 'Kötü Statü' listesindeyse (Kapalı, Çözüldü vs.)
            if current_status in SC_BAD_STATUS_IDS:
                
                # --- HEDEF BELİRLEME ---
                final_target = 78 if (agent_id and agent_id > 0) else 1
                
                log(f"⚠️ MÜDAHALE: Ticket {t_id} (Statü: {current_status}) -> Hedef: {final_target}")
                
                operation_success = False
                
                # --- SENARYO 1: TICKET KAPALIYSA (Status: 2) ---
                if current_status == 2:
                    log(f"   -> [Senaryo: Kapalı] Önce 1'e çekiliyor (Uyandırma)...")
                    ok1, msg1 = update_status(t_id, 1) 
                    
                    if ok1:
                        if final_target == 78:
                            time.sleep(1) # Hata almamak için minik bekleme
                            log(f"   -> [Senaryo: Kapalı] Şimdi 78'e çekiliyor (Atama)...")
                            ok2, msg2 = update_status(t_id, 78) 
                            if ok2: operation_success = True
                            else: log(f"   -> ❌ 78 yapılamadı, 1 olarak kaldı. Hata: {msg2}")
                        else:
                            operation_success = True 
                    else:
                        log(f"   -> ❌ Uyandırma başarısız. Hata: {msg1}")

                # --- SENARYO 2: TICKET ÇÖZÜLDÜYSE (Status: 83 vb.) ---
                else:
                    log(f"   -> [Senaryo: Aktif/Çözüldü] Direkt {final_target} yapılıyor...")
                    ok, msg = update_status(t_id, final_target)
                    if ok: operation_success = True
                    else: log(f"   -> ❌ Güncelleme başarısız. Hata: {msg}")

                # --- SONUÇ BİLDİRİMİ ---
                if operation_success:
                    log(f"✅ Ticket {t_id} kurtarıldı.")
                    
                    sc_post(f'Incident/{t_id}/Conversations/Add', {
                        "description": "Zabbix alarmı devam ettiği için otomasyon tarafından statü güncellendi.",
                        "isPrivate": True, "noteType": 1
                    })
                    
                    ticket_url = f"{SC_PANEL_URL}/Ticket/EditV2?id={t_id}"
                    zbx_msg = f"AWX Automation: Ticket {t_id} updated. | URL={ticket_url}"
                    zbx_req("event.acknowledge", {"eventids": [e_id], "action": 4, "message": zbx_msg})
            
            else:
                # log(f"ℹ️ PAS GEÇİLDİ: Ticket {t_id} statüsü uygun ({current_status}). Müdahale gerekmez.")
                pass
                    
        except Exception as e:
            log(f"Hata: {e}")

if __name__ == "__main__":
    if not SC_API_URL: 
        log("API URL Eksik")
        exit(1)
        
    log(f"--- ServiceCore Advanced Logic Sync (Son 30 Gün / Ack Hariç) ---")
    
    targets = get_active_problems_with_ticket_ids()
    if targets:
        log(f"İşlenecek: {len(targets)}")
        # Hız dengesi için 4 thread (10 hata veriyor, 1 yavaş kalıyor)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(check_and_enforce_workflow, targets)
    else:
        log("İşlenecek kayıt yok.")
    log("Bitti.")
