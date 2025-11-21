from scapy.all import IP, TCP, UDP
import numpy as np

IDLE_TIMEOUT = 1000000

class Flow:
    def __init__(self, packet_tuple):
        pyshark_pkt, scapy_pkt = packet_tuple
        
        self.key = self._get_flow_key(pyshark_pkt)
        self.packets = []
        
        self.start_time = float(pyshark_pkt.sniff_timestamp)
        self.latest_timestamp = self.start_time

        self.flow_interarrival_time = []
        self.init_window_size = {'forward': -1, 'backward': -1}
        
        self.start_active = self.start_time
        self.last_active = self.start_time
        self.active = []
        self.idle = []
        
        self.timestamp_A = 0  # SYN time
        self.timestamp_B = 0  # SYN/ACK time
        self.timestamp_C = 0  # First ACK time
        self.client_ttl = 0
        self.server_ttl = 0
        
        self.add_packet(packet_tuple)

    def _get_flow_key(self, pkt):
        src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
        proto = pkt.transport_layer.lower()
        if proto == 'tcp' or proto == 'udp':
            sport, dport = int(pkt[proto].srcport), int(pkt[proto].dstport)
            if (src_ip, sport) < (dst_ip, dport):
                return (src_ip, sport, dst_ip, dport, proto)
            else:
                return (dst_ip, dport, src_ip, sport, proto)
        return None

    def add_packet(self, packet_tuple):
        pyshark_pkt, scapy_pkt = packet_tuple
        pkt_time = float(pyshark_pkt.sniff_timestamp)
        
        if self.packets:
            iat = (pkt_time - self.latest_timestamp) * 1e6
            self.flow_interarrival_time.append(iat)
            
            if iat > IDLE_TIMEOUT:
                active_duration = self.last_active - self.start_active
                if active_duration > 0:
                    self.active.append(active_duration * 1e6)
                self.idle.append(iat)
                self.start_active = pkt_time
        
        self.last_active = pkt_time
        self.latest_timestamp = pkt_time

        packet_data = {
            "pyshark_pkt": pyshark_pkt,
            "scapy_pkt": scapy_pkt,
            "tcp_flags": str(pyshark_pkt.tcp.flags) if 'TCP' in pyshark_pkt else "",
            "timestamp": pkt_time
        }
        self.packets.append(packet_data)
        
        if 'TCP' in pyshark_pkt and scapy_pkt and scapy_pkt.haslayer(TCP):
            flags = scapy_pkt[TCP].flags

            flow_initiator_ip = self.packets[0]["pyshark_pkt"].ip.src
            
            if flags.S and not flags.A and pyshark_pkt.ip.src == flow_initiator_ip:
                if self.timestamp_A == 0:
                    self.timestamp_A = pkt_time
                    self.client_ttl = int(pyshark_pkt.ip.ttl)
            elif flags.S and flags.A and pyshark_pkt.ip.dst == flow_initiator_ip:
                if self.timestamp_B == 0:
                    self.timestamp_B = pkt_time
                    self.server_ttl = int(pyshark_pkt.ip.ttl)
            elif flags.A and not flags.S and self.timestamp_A > 0 and self.timestamp_B > 0:
                if self.timestamp_C == 0:
                    self.timestamp_C = pkt_time

            if pyshark_pkt.ip.src == flow_initiator_ip:
                if self.init_window_size['forward'] == -1:
                    self.init_window_size['forward'] = int(pyshark_pkt.tcp.window_size)
            else:
                if self.init_window_size['backward'] == -1:
                    self.init_window_size['backward'] = int(pyshark_pkt.tcp.window_size)

class FlowReassembler:
    def __init__(self, timeout=60):
        self.flows = {}
        self.timeout = timeout

    def process_packet(self, packet_tuple):
        pyshark_pkt, _ = packet_tuple
        if 'IP' not in pyshark_pkt:
            return None

        flow_key = self._get_flow_key(pyshark_pkt)
        if not flow_key:
            return None

        if flow_key not in self.flows:
            self.flows[flow_key] = Flow(packet_tuple)
        else:
            self.flows[flow_key].add_packet(packet_tuple)
        
        return self.check_for_expired_flows(float(pyshark_pkt.sniff_timestamp))

    def _get_flow_key(self, pkt):
        try:
            src_ip, dst_ip = pkt.ip.src, pkt.ip.dst
            proto = pkt.transport_layer.lower()
            if proto in ['tcp', 'udp']:
                sport, dport = int(pkt[proto].srcport), int(pkt[proto].dstport)
                if (src_ip, sport) < (dst_ip, dport):
                    return (src_ip, sport, dst_ip, dport, proto)
                else:
                    return (dst_ip, dport, src_ip, sport, proto)
        except AttributeError:
            return None
        return None

    def check_for_expired_flows(self, current_time):
        expired_flows = []
        keys_to_delete = []
        for key, flow in self.flows.items():
            is_finished = False
            if flow.packets:
                last_packet_data = flow.packets[-1]
                if 'f' in last_packet_data.get("tcp_flags", "") or 'r' in last_packet_data.get("tcp_flags", ""):
                    is_finished = True
            
            if is_finished or (current_time - flow.latest_timestamp > self.timeout):
                final_active = flow.last_active - flow.start_active
                if final_active > 0:
                    flow.active.append(final_active * 1e6)

                expired_flows.append(flow)
                keys_to_delete.append(key)
        
        for key in keys_to_delete:
            del self.flows[key]
            
        return expired_flows
    
    def flush_all_flows(self):
        all_flows = list(self.flows.values())
        for flow in all_flows:
            final_active = flow.last_active - flow.start_active
            if final_active > 0:
                flow.active.append(final_active * 1e6)
        self.flows.clear()
        return all_flows