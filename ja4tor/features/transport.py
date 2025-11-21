import numpy as np
from scapy.all import TCP

def extract_transport(flow):
    features = {}

    flow_initiator_ip = flow.packets[0]["pyshark_pkt"].ip.src
    fwd_packets_scapy = [p["scapy_pkt"] for p in flow.packets if p["pyshark_pkt"].ip.src == flow_initiator_ip and p["scapy_pkt"]]
    bwd_packets_scapy = [p["scapy_pkt"] for p in flow.packets if p["pyshark_pkt"].ip.src != flow_initiator_ip and p["scapy_pkt"]]
    
    fwd_lengths = [len(p) for p in fwd_packets_scapy]
    bwd_lengths = [len(p) for p in bwd_packets_scapy]
    all_lengths = [len(p["scapy_pkt"]) for p in flow.packets if p["scapy_pkt"]]

    features['Total Fwd Packets'] = len(fwd_packets_scapy)
    features['Total Bwd Packets'] = len(bwd_packets_scapy)
    features['Total Length of Fwd Packets'] = sum(fwd_lengths)
    features['Total Length of Bwd Packets'] = sum(bwd_lengths)

    features['Fwd Packet Length Max'] = np.max(fwd_lengths) if fwd_lengths else 0
    features['Fwd Packet Length Min'] = np.min(fwd_lengths) if fwd_lengths else 0
    features['Fwd Packet Length Mean'] = np.mean(fwd_lengths) if fwd_lengths else 0
    features['Fwd Packet Length Std'] = np.std(fwd_lengths) if fwd_lengths else 0
    features['Bwd Packet Length Max'] = np.max(bwd_lengths) if bwd_lengths else 0
    features['Bwd Packet Length Min'] = np.min(bwd_lengths) if bwd_lengths else 0
    features['Bwd Packet Length Mean'] = np.mean(bwd_lengths) if bwd_lengths else 0
    features['Bwd Packet Length Std'] = np.std(bwd_lengths) if bwd_lengths else 0
    features['Packet Length Variance'] = np.var(all_lengths) if all_lengths else 0

    flags = {'F': 0, 'S': 0, 'R': 0, 'P': 0, 'A': 0}
    for p in flow.packets:
        if p["scapy_pkt"] and p["scapy_pkt"].haslayer(TCP):
            for flag in p["scapy_pkt"][TCP].flags:
                if flag in flags:
                    flags[flag] += 1
    
    features['FIN Flag Count'] = flags['F']
    features['SYN Flag Count'] = flags['S']
    features['RST Flag Count'] = flags['R']
    features['PSH Flag Count'] = flags['P']
    features['ACK Flag Count'] = flags['A']

    features['Down/Up Ratio'] = len(bwd_packets_scapy) / len(fwd_packets_scapy) if len(fwd_packets_scapy) > 0 else 0
    features['Average Packet Size'] = np.mean(all_lengths) if all_lengths else 0
    features['Avg Fwd Segment Size'] = features['Fwd Packet Length Mean']
    features['Avg Bwd Segment Size'] = features['Bwd Packet Length Mean']
    
    features['Init_Win_bytes_forward'] = flow.init_window_size['forward']
    features['Init_Win_bytes_backward'] = flow.init_window_size['backward']

    return features