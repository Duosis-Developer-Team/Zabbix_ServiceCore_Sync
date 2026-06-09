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

# URL Protokol Kontrolü (Başına http/https eklenmediyse otomatik düzeltir)
ZBX_API_URL = os.getenv("ZBX_API_URL", "")
if ZBX_API_URL and not ZBX_API_URL.startswith(("http://", "https://")):
    ZBX_API_URL = f"http://{ZBX_API_URL}"

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
        r = requests.post(
            ZBX_API_URL, 
            json={"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}, 
            timeout=15, 
            verify=False
        )
        response_json = r.json()
        if "error" in response_json:
            log(f"❌ Zabbix API Hatası ({method}): {response_json['error'].get('data', response_json['error'].get('message'))}")
        return response_json.get('result')
    except Exception as e: 
        log(f"❌ Zabbix API Bağlantı Hatası ({method}): {e}")
        return None

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
    # --- SON 30 GÜN HESABI ---
    time_from = int(time.time()) - (30 * 24 * 60 * 60)
    
    log("Zabbix 7.0 Açık Problemleri taranıyor...")
    
    # Adım 1: problem.get ile sadece açık olan ve ack edilmemiş eventid'leri topluyoruz
    prob_params = {
        "output": ["eventid", "clock"],
        "acknowledged": False, 
        "sortfield": ["eventid"], 
        "sortorder": "DESC"
    }
    
    problems = zbx_req("problem.get", prob_params)
    if not problems: 
        log("Açık ve Onaylanmamış problem bulunamadı.")
        return []
        
    # Son 30 gün içinde olan event ID'lerini filtrele
    event_ids = [p['eventid'] for p in problems if int(p.get('clock', 0)) >= time_from]
    if not event_ids:
        log("Son 30 güne ait aktif problem ID'si yok.")
        return []

    log(f"Bulunan {len(event_ids)} adet problem için event detayları ve notlar çekiliyor...")

    # Adım 2: Toplanan eventid'ler ile event.get metodunu çağırıp notları (acknowledges) çekiyoruz
    event_params = {
        "output": ["eventid"],
        "eventids": event_ids,
        "select_acknowledges": ["message"]
    }
    
    events = zbx_req("event.get", event_params)
    if not events: return []
    
    targets = []
    for e in events:
        acknowledges = e.get('acknowledges', [])
        if not acknowledges:
            continue 
            
        for ack in acknowledges:
            msg = ack.get('message', '')
            match = re.search(r'ServiceCoreID\s*=\s*(\d+)', msg, re.IGNORECASE)
            
            if match:
                targets.append({
                    "event_id": e.get('eventid'), 
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
                    
                    # Zabbix harici API'de event'e mesaj eklemek için 'event.acknowledge' metoduna geri dönüldü
                    zbx_req("event.acknowledge", {
                        "eventids": [e_id], 
                        "action": 4, # 4: Add message standardı Zabbix 7.0'da da korunmaktadır
                        "message": zbx_msg
                    })
            
            else:
                pass
                    
        except Exception as e:
            log(f"Hata: {e}")

if __name__ == "__main__":
    if not SC_API_URL: 
        log("API URL Eksik")
        exit(1)
        
    log(f"--- ServiceCore Advanced Logic Sync (Zabbix 7.0 LTS Ready) ---")
    
    targets = get_active_problems_with_ticket_ids()
    if targets:
        log(f"İşlenecek: {len(targets)}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            executor.map(check_and_enforce_workflow, targets)
    else:
        log("İşlenecek kayıt yok.")
    log("Bitti.")
