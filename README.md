# StartHere_CS_04
Network Packet Analyzer


from scapy.all import *


# Callback function to analyze each packet
def packet_callback(packet):
    if packet.haslayer(IP):
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        protocol = packet.proto

        # Check for TCP, UDP, or ICMP protocols
        if protocol == 6:
            protocol_name = "TCP"
        elif protocol == 17:
            protocol_name = "UDP"
        elif protocol == 1:
            protocol_name = "ICMP"
        else:
            protocol_name = "Other"

      
        payload = packet.payload if packet.haslayer(Raw) else "No Payload"

        # Print captured packet information
        print(f"Source IP: {source_ip} -> Destination IP: {destination_ip}")
        print(f"Protocol: {protocol_name}")
        print(f"Payload: {payload}")
        print("-" * 40)


# Start sniffing on all interfaces 
print("Starting packet capture...")
sniff(prn=packet_callback, store=0, count=10)  
print("Packet capture complete.")
