from scapy.all import sniff, Ether, IP

def packet_handler(packet):
    if Ether in packet and IP in packet:
        # Extract relevant information from the packet
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        packet_size = len(packet)
        
        # Display the extracted information
        print(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}, Packet Size: {packet_size}")

# Sniff packets on the network interface
# You can specify additional parameters like filters, timeout, etc.
sniff(prn=packet_handler, count=20)  # Sniff 20 packets