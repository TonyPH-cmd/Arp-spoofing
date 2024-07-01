from scapy.all import *
import os

# Función para obtener la dirección MAC de una IP dada
def obtener_mac(ip):
    ans, unans = arping(ip)
    for s, r in ans:
        return r[Ether].src
    return None

# Función para verificar si la dirección MAC en la tabla ARP coincide con la dirección MAC real
def verificar_arp(ip_router, mac_esperada):
    arp_table = arping(ip_router)
    for s, r in arp_table[0]:
        mac_actual = r[Ether].src
        if mac_actual.lower() == mac_esperada.lower():
            return True
        else:
            return False
    return False

if __name__ == "__main__":
    # Verificar si el script se está ejecutando como root
    if os.geteuid() != 0:
        print("Debes ejecutar este script como root")
        sys.exit(1)

    # Solicitar la IP del router
    ip_router = input("Introduce la dirección IP del router: ")

    # Obtener la dirección MAC real del router
    mac_real = obtener_mac(ip_router)
    if mac_real is None:
        print("Error al obtener la dirección MAC del router")
        sys.exit(1)

    print(f"La dirección MAC real del router es: {mac_real}")

    # Verificar si la dirección MAC en la tabla ARP coincide con la dirección MAC real
    if verificar_arp(ip_router, mac_real):
        print("La dirección MAC del router en la tabla ARP no ha sido modificada.")
    else:
        print("¡ALERTA! La dirección MAC del router en la tabla ARP ha sido modificada.")
