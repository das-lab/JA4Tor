import numpy as np

def extract_performance(flow):
    features = {}
    duration_us = (flow.latest_timestamp - flow.start_time) * 1e6
    duration_s = duration_us / 1e6
    
    features['Flow Duration'] = duration_us
    
    total_bytes = sum(len(p["scapy_pkt"]) for p in flow.packets if p["scapy_pkt"])
    features['Flow Bytes/s'] = total_bytes / duration_s if duration_s > 0 else 0
    features['Flow Packets/s'] = len(flow.packets) / duration_s if duration_s > 0 else 0

    iats = flow.flow_interarrival_time
    features['Flow IAT Mean'] = np.mean(iats) if iats else 0
    features['Flow IAT Std'] = np.std(iats) if iats else 0
    features['Flow IAT Max'] = np.max(iats) if iats else 0
    features['Flow IAT Min'] = np.min(iats) if iats else 0

    flow_initiator_ip = flow.packets[0]["pyshark_pkt"].ip.src
    fwd_timestamps = [p["timestamp"] for p in flow.packets if p["pyshark_pkt"].ip.src == flow_initiator_ip]
    bwd_timestamps = [p["timestamp"] for p in flow.packets if p["pyshark_pkt"].ip.src != flow_initiator_ip]
    
    fwd_iats = np.diff(fwd_timestamps) * 1e6
    bwd_iats = np.diff(bwd_timestamps) * 1e6
    
    features['Fwd IAT Total'] = np.sum(fwd_iats) if len(fwd_iats) > 1 else 0
    features['Fwd IAT Mean'] = np.mean(fwd_iats) if len(fwd_iats) > 0 else 0
    features['Fwd IAT Std'] = np.std(fwd_iats) if len(fwd_iats) > 0 else 0
    features['Fwd IAT Max'] = np.max(fwd_iats) if len(fwd_iats) > 0 else 0
    features['Fwd IAT Min'] = np.min(fwd_iats) if len(fwd_iats) > 0 else 0

    features['Bwd IAT Total'] = np.sum(bwd_iats) if len(bwd_iats) > 1 else 0
    features['Bwd IAT Mean'] = np.mean(bwd_iats) if len(bwd_iats) > 0 else 0
    features['Bwd IAT Std'] = np.std(bwd_iats) if len(bwd_iats) > 0 else 0
    features['Bwd IAT Max'] = np.max(bwd_iats) if len(bwd_iats) > 0 else 0
    features['Bwd IAT Min'] = np.min(bwd_iats) if len(bwd_iats) > 0 else 0

    active_times = flow.active
    idle_times = flow.idle
    
    features['Active Mean'] = np.mean(active_times) if active_times else 0
    features['Active Std'] = np.std(active_times) if active_times else 0
    features['Active Max'] = np.max(active_times) if active_times else 0
    features['Active Min'] = np.min(active_times) if active_times else 0

    features['Idle Mean'] = np.mean(idle_times) if idle_times else 0
    features['Idle Std'] = np.std(idle_times) if idle_times else 0
    features['Idle Max'] = np.max(idle_times) if idle_times else 0
    features['Idle Min'] = np.min(idle_times) if idle_times else 0

    def epoch_diff_ms(t1, t2):
        return abs(t2 - t1) * 1000

    features['client_latency'] = 0.0
    features['server_latency'] = 0.0

    if flow.timestamp_B > 0 and flow.timestamp_A > 0:
        features['client_latency'] = epoch_diff_ms(flow.timestamp_A, flow.timestamp_B)
    
    if flow.timestamp_C > 0 and flow.timestamp_B > 0:
        features['server_latency'] = epoch_diff_ms(flow.timestamp_B, flow.timestamp_C)

    return features