from scapy.all import *

# Función para interceptar, modificar y reenviar el paquete
def packet_callback(pkt):
    try:
        # Filtrar los paquetes TCP que estén dirigidos al puerto 22 (SSH)
        if pkt.haslayer(TCP) and pkt.dport == 22:
            if pkt.haslayer(Raw):
                # Mostrar el contenido original del saludo SSH en formato hexadecimal
                original_data = pkt[Raw].load.hex()
                print("Original Data (Hex): {}".format(original_data))

                # Buscar el saludo SSH específico "SSH-2.0-" en la carga útil
                if b"SSH-2.0-" in pkt[Raw].load:
                    # Reemplazar la parte del saludo SSH con la nueva cadena "SSH-2.0-OpenSSH_?"
                    new_data = b"SSH-2.0-OpenSSH_?" + pkt[Raw].load[17:]  # Modificar solo la parte inicial

                    # Reemplazar la carga útil del paquete con la nueva cadena
                    pkt[Raw].load = new_data

                    # Mostrar los datos modificados en formato hexadecimal
                    modified_data = pkt[Raw].load.hex()
                    print("Modified Data (Hex): {}".format(modified_data))

                    # Reenviar el paquete modificado
                    send(pkt)
                else:
                    print("No SSH-2.0 saludo encontrado en el paquete.")
            else:
                print("Paquete sin carga útil Raw.")
        else:
            print("Paquete no es TCP o no está destinado al puerto 22 (SSH).")

    except Exception as e:
        print("Error al procesar el paquete: {}".format(e))

# Iniciar el sniffing de paquetes en la interfaz de red (se escuchan solo los paquetes SSH)
sniff(filter="tcp port 22", prn=packet_callback, store=0)
