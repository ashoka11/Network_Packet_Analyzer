import scapy.all as scapy
def packet_callback(packet):
    if packet.haslayer(scapy.IP):
        source_ip = packet[scapy.IP].src
        destination_ip = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto

        print(f"Packet Captured: Source IP - {source_ip}, Destination IP - {destination_ip}, Protocol - {protocol}")

        if packet.haslayer(scapy.TCP):
            payload = packet[scapy.Raw].load
            print(f"TCP Payload: {payload.decode('utf-8', 'ignore')}")

        elif packet.haslayer(scapy.UDP):
            payload = packet[scapy.Raw].load
            print(f"UDP Payload: {payload.decode('utf-8', 'ignore')}")

def main():
    interface = input("Enter the interface to sniff on (e.g., eth0): ")

    try:
        scapy.sniff(iface=interface, store=False, prn=packet_callback)
    except PermissionError:
        print("Insufficient privileges. Run the script with administrator/superuser privileges.")

if __name__ == "__main__":
    main()