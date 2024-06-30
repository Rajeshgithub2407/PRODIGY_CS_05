from scapy.all import sniff, IP, TCP, UDP, Raw

def packet_callback(packet):
    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        
        # Check for protocols and extract payload data if present
        if TCP in packet:
            tcp_layer = packet[TCP]
            print(f"Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            udp_layer = packet[UDP]
            print(f"Protocol: UDP")
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        else:
            print(f"Protocol: {ip_layer.proto}")
        
        # Extract payload data if present
        if Raw in packet:
            payload = packet[Raw].load
            print(f"Payload: {payload}")
        print("-" * 80)

def start_sniffing(interface):
    print(f"Starting packet capture on interface {interface}")
    sniff(iface=interface, prn=packet_callback, store=False)

if __name__ == "__main__":
    # Replace 'eth0' with your network interface name
    interface = "eth0"
    start_sniffing(interface)
