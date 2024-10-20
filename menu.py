import pyshark

def display_menu():
    print("\n=== PyShark Packet Analyzer ===")
    print("1. Captura de paquetes en vivo")
    print("2. Análisis de archivo PCAP")
    print("3. Filtrar paquetes")
    print("4. Exportar datos")
    print("5. Salir")

def live_capture():
    interface = input("Introduce la interfaz de red (ejemplo: eth0): ")
    capture = pyshark.LiveCapture(interface=interface)
    capture.sniff(timeout=10)  # Captura durante 10 segundos
    print("\nPaquetes capturados:")
    for packet in capture:
        print(packet)

def analyze_pcap():
    file_path = input("Introduce la ruta del archivo PCAP: ")
    capture = pyshark.FileCapture(file_path)
    print("\nPaquetes en el archivo PCAP:")
    for packet in capture:
        print(packet)

def filter_packets():
    # Aquí puedes implementar la funcionalidad de filtrado
    print("Funcionalidad de filtrado aún no implementada.")

def export_data():
    # Aquí puedes implementar la funcionalidad de exportación
    print("Funcionalidad de exportación aún no implementada.")

def main():
    while True:
        display_menu()
        choice = input("Selecciona una opción: ")

        if choice == '1':
            live_capture()
        elif choice == '2':
            analyze_pcap()
        elif choice == '3':
            filter_packets()
        elif choice == '4':
            export_data()
        elif choice == '5':
            print("Saliendo...")
            break
        else:
            print("Opción no válida. Inténtalo de nuevo.")

if __name__ == "__main__":
    main()
