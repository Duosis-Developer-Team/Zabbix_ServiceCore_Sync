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

# DNS Override (Senin ortamına özel)
ZBX_DOMAIN = "watchman.bulutistan.com"
ZBX_REAL_IP = "10.6.116.178"

# --- MÜDAHALE EDİLECEK "KÖTÜ" STATÜLER ---
# 2: Kapalı, 83: Çözüldü, 94: İptal, 46: Tamamlanmış, 65: Ertelenen
bad_ids_str = os.getenv("SC_BAD_STATUS_IDS", "2, 83, 94, 46, 65")
SC_BAD_STATUS_IDS = [int(x.strip()) for x in bad_ids_str.split(',') if x.strip()]

# DNS Override Logic
prv_getaddrinfo = socket.getaddrinfo
def new_getaddrinfo(*args):
    if args[0] == ZBX_DOMAIN: return prv_getaddrinfo(ZBX_REAL_IP, *args[1:])
    return prv_getaddrinfo(*args)
socket.getaddrinfo = new_getaddrinfo

# ================= HELPERS =================
def log(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}")

def zbx_req(method, params):
    try:
        # Verify=False SSL hatalarını görmezden gelir
        r = requests.post(ZBX_API_URL, json={"jsonrpc": "2.0", "method": method, "params": params, "auth": ZBX_API_TOKEN, "id": 1}, timeout=15, verify=False)
        return r.json().get('result')
    except Exception as e:
        log(f"Zabbix API Error: {e}")
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
    # --- DEĞİŞİKLİK: SON 30 GÜN HESABI ---
    # Şu anki zaman (epoch) - (30 gün * 24 saat * 60 dk * 60 sn)
    time_from = int(time.time()) - (30 * 24 * 60 * 60)
    
    log("Zabbix problemleri taranıyor (Son 30 gün & Mesajı Olanlar)...")
    
    params = {
        "output": ["eventid", "name", "acknowledged"],
        "selectAcknowledges": "extend", # Mesajları (Notları) getir
        "time_from": time_from,         # Limit yerine tarih kısıtı
        "sortfield": ["eventid"], 
        "sortorder": "DESC"
        # "limit": 1000  <-- Limit kaldırıldı
    }
    
    problems = zbx_req("problem.get", params)
    if not problems: return []
    
    targets = []
    for p in problems:
        # --- FİLTRE: SADECE NOT GİRİLMİŞLERİ AL ---
        acks = p.get('acknowledges', [])
        if not acks:
            continue # Hiç not yoksa atla
            
        found_ticket = False
        for ack in acks:
            msg = ack.get('message', '')
            # Regex ile ServiceCoreID=12345 yapısını ara
            match = re.search(r'ServiceCoreID\s*=\s*(\d+)', msg, re.IGNORECASE)
            
            if match:
                targets.append({
                    "event_id": p.get('eventid'), 
                    "ticket_id": match.group(1)
                })
                found_ticket = True
                break # İlk ID'yi bulunca döngüden çık
    
    return targets

def update_status(ticket_id, status_id):
    """ServiceCore Statü Güncelleme"""
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
            
            # 2. Eğer Ticket 'Kötü Statü' listesindeyse (Kapalı, Çözüldü, İptal vs.)
            if current_status in SC_BAD_STATUS_IDS:
                
                # --- HEDEF BELİRLEME ---
                # Eğer Agent varsa 78 (Atandı), yoksa 1 (Yeni)
                # NOT: Agent yokken de zorla 78 olsun istersen burayı "final_target = 78" yap.
                final_target = 78 if (agent_id and agent_id > 0) else 1
                
                log(f"⚠️ MÜDAHALE: Ticket {t_id} (Mevcut: {current_status}) -> Hedef: {final_target}")
                
                operation_success = False
                
                # --- SENARYO 1: TICKET TAMAMEN KAPALIYSA (Status: 2) ---
                # ServiceCore kuralı: Kapalı ticket direkt başka statüye geçmez, önce açılmalı.
                if current_status == 2:
                    log(f"   -> [Senaryo: Kapalı] Önce 1'e çekiliyor (Uyandırma)...")
                    ok1, msg1 = update_status(t_id, 1) 
                    
                    if ok1:
                        # Eğer hedefimiz 78 ise, şimdi 1'den 78'e çekiyoruz
                        if final_target == 78:
                            time.sleep(1) # API nefes alsın
                            log(f"   -> [Senaryo: Kapalı] Şimdi 78'e çekiliyor (Atama)...")
                            ok2, msg2 = update_status(t_id, 78) 
                            if ok2: operation_success = True
                            else: log(f"   -> ❌ 78 yapılamadı, 1 olarak kaldı. Hata: {msg2}")
                        else:
                            operation_success = True 
                    else:
                        log(f"   -> ❌ Uyandırma başarısız. Hata: {msg1}")

                # --- SENARYO 2: TICKET ÇÖZÜLDÜYSE (Status: 83 vb.) ---
                # Çözüldü statüsünden direkt Atandı/Yeni statüsüne geçilebilir.
                else:
                    log(f"   -> [Senaryo: Aktif/Çözüldü] Direkt {final_target} yapılıyor...")
                    ok, msg = update_status(t_id, final_target)
                    if ok: operation_success = True
                    else: log(f"   -> ❌ Güncelleme başarısız. Hata: {msg}")

                # --- SONUÇ BİLDİRİMİ VE LOGLAMA ---
                if operation_success:
                    log(f"✅ Ticket {t_id} başarıyla kurtarıldı.")
                    
                    # ServiceCore'a not düş
                    sc_post(f'Incident/{t_id}/Conversations/Add', {
                        "description": "Zabbix alarmı devam ettiği için otomasyon (AWX) tarafından statü tekrar açıldı.",
                        "isPrivate": True, "noteType": 1
                    })
                    
                    # Zabbix'e not düş (Tekrar tekrar işlem yapmamak için de faydalı olabilir)
                    ticket_url = f"{SC_PANEL_URL}/Ticket/EditV2?id={t_id}"
                    zbx_msg = f"AWX Automation: Ticket {t_id} Re-opened based on active problem. | URL={ticket_url}"
                    zbx_req("event.acknowledge", {"eventids": [e_id], "action": 4, "message": zbx_msg})
            
            else:
                # Ticket zaten açık (Yeni, Atandı, Beklemede vs.)
                # log(f"ℹ️ PAS GEÇİLDİ: Ticket {t_id} zaten uygun statüde ({current_status}).")
                pass
                    
        except Exception as e:
            log(f"Logic Error Ticket {t_id}: {e}")

if __name__ == "__main__":
    if not SC_API_URL: 
        log("HATA: API URL Environment Variable Eksik!")
        exit(1)
        
    log(f"--- ServiceCore Advanced Logic Sync (Son 30 Gün) ---")
    
    # 1. Problemleri Bul
    targets = get_active_problems_with_ticket_ids()
    
    if targets:
        log(f"İncelenecek Potansiyel Kayıt Sayısı: {len(targets)}")
        
        # 2. Paralel İşleme (Hız için)
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            executor.map(check_and_enforce_workflow, targets)
    else:
        log("İşlenecek kriterlere uygun kayıt bulunamadı.")
    
    log("İşlem Tamamlandı.")
