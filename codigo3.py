from scapy.all import *

# Función para interceptar, modificar y reenviar el paquete
def packet_callback(pkt):
    # Filtrar los paquetes TCP que estén dirigidos al puerto 22 (SSH)
    if pkt.haslayer(TCP) and pkt.dport == 22:
        if pkt.haslayer(Raw):
            # Mostrar el contenido original del paquete en formato hexadecimal
            original_data = pkt[Raw].load.hex()
            print("Original Data (Hex): {}".format(original_data))

            # Buscar el saludo SSH específico "SSH-2.0-OpenSSH_"
            if b"SSH-2.0-" in pkt[Raw].load:
                # Modificar la parte inicial del saludo SSH
                new_data = b"SSH-2.0-OpenSSH_?" + pkt[Raw].load[17:]  # Solo modificar la parte inicial

                # Modificar el Key Exchange Init, eliminando parte de los algoritmos para reducir el tamaño
                # (Este es solo un ejemplo, la modificación depende de los datos específicos de Key Exchange Init)
                kex_init = pkt[Raw].load[17:]  # Aquí tomamos la parte del Key Exchange Init
                if len(kex_init) > 300:
                    # Reducir el tamaño del Key Exchange Init eliminando opciones
                    kex_init = kex_init[:300]  # Cortar el paquete a 300 bytes (esto es solo un ejemplo)

                # Reemplazar la carga útil del paquete con la nueva cadena
                pkt[Raw].load = b"SSH-2.0-OpenSSH_?" + kex_init

                # Mostrar los datos modificados en formato hexadecimal
                modified_data = pkt[Raw].load.hex()
                print("Modified Data (Hex): {}".format(modified_data))

                # Verificar si el paquete es menor de 300 bytes y reenviarlo
                if len(pkt[Raw].load) < 300:
                    print(f"Paquete modificado exitosamente y con tamaño menor a 300 bytes.")
                    # Reenviar el paquete modificado
                    send(pkt)
                else:
                    print(f"El paquete sigue siendo mayor a 300 bytes.")

# Iniciar el sniffing de paquetes en la interfaz de red (se escuchan solo los paquetes SSH)
sniff(filter="tcp port 22", prn=packet_callback, store=0)
