from datetime import datetime
from scapy.all import IP

def extract_identification(flow):

    key_src_ip, key_src_port, key_dst_ip, key_dst_port, proto = flow.key
    
    first_packet = flow.packets[0].get("pyshark_pkt")
    if not first_packet:
        src_ip, src_port, dst_ip, dst_port = key_src_ip, key_src_port, key_dst_ip, key_dst_port
    else:
        actual_src_ip = first_packet.ip.src
        if actual_src_ip == key_src_ip:
            src_ip, src_port, dst_ip, dst_port = key_src_ip, key_src_port, key_dst_ip, key_dst_port
        else:
            src_ip, src_port, dst_ip, dst_port = key_dst_ip, key_dst_port, key_src_ip, key_src_port


    flow_string_representation = f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto}"
    flow_id = abs(hash(flow_string_representation))

    return {
        'Flow ID': flow_id,
        'Src IP': src_ip,
        'Src Port': src_port,
        'Dst IP': dst_ip,
        'Dst Port': dst_port,
        'Protocol': proto,
        'Timestamp': datetime.fromtimestamp(flow.start_time).strftime('%Y-%m-%d %H:%M:%S')
    }