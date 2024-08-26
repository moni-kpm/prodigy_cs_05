from scapy.all import sniff

log_file = "key_log.txt"
#the output will be in the key_log.txt

def process_packet(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto

        protocol_str = "TCP" if protocol == 6 else "UDP" if protocol == 17 else str(protocol)

        with open(log_file, "a") as f:
            f.write(f"Source IP: {src_ip}\n")
            f.write(f"Destination IP: {dst_ip}\n")
            f.write(f"Protocol: {protocol_str}\n")

            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                formatted_payload = format_payload(payload)
                f.write(f"Payload: {formatted_payload}\n")

            f.write("\n" + "-"*50 + "\n")

t
def format_payload(payload):
    try:
      
        return payload.decode('ascii', errors='replace')
    except Exception:
       
        return ' '.join(f"{byte:02x}" for byte in payload)
sniff(filter="ip", prn=process_packet, count=10)