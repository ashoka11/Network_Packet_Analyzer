# Network_Packet_Analyzer

Network Packet Sniffer using Scapy

Overview:
This Python script utilizes the scapy library to create a basic network packet sniffer. The script captures packets on a specified network interface, extracts information such as source and destination IP addresses, and prints details about the captured packets.

Installation:
  To install the required scapy library, execute the following command:
    pip install scapy

Usage:
1. Install the scapy library as mentioned above.
2. Run the script by executing the packet_sniffer.py file.
3. Enter the desired network interface to sniff on (e.g., eth0) when prompted.
4. The script will capture packets on the specified interface and print information about the packets, including source and destination IP addresses and protocol.
5. Terminate the script by manually stopping the execution.

Code:
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

Notes:
* The script captures packets using the scapy.sniff function, and the packet_callback function is called for each captured packet.
* The script extracts information such as source and destination IP addresses, protocol, and prints details about the packets.
* CAUTION: Network packet sniffing may raise privacy and ethical concerns. Ensure that you have appropriate authorization before deploying or using such a tool.
* Use this script responsibly and only in scenarios where it complies with legal and ethical standards.
