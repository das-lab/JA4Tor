from .identification import extract_identification
from .transport import extract_transport
from .performance import extract_performance
from .application import extract_application
from .security import extract_security

HEADER = [
    'Flow ID', 'Src IP', 'Src Port', 'Dst IP', 'Dst Port', 'Protocol', 'Timestamp',
    'Total Fwd Packets', 'Total Bwd Packets', 'Total Length of Fwd Packets', 'Total Length of Bwd Packets',
    'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 'Bwd Packet Length Std',
    'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count',
    'ACK Flag Count', 'Down/Up Ratio',
    'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Init_Win_bytes_forward',
    'Init_Win_bytes_backward', 'Flow Duration', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 
    'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 
    'Bwd IAT Min', 'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 
    'Idle Max', 'Idle Min', 'client_latency', 'server_latency', 

    'http_method', 'http_host_hash', 'http_user_agent_hash', 'http_path_len', 'tls_sni_domain',

    'http_req_method_short', 'http_req_version', 'http_req_has_cookie', 'http_req_has_referer',
    'http_req_header_count', 'http_req_has_lang', 'http_req_header_hash', 'http_req_cookie_hash',

    'tls_client_ptype', 'tls_client_version', 'tls_client_sni_presence', 'tls_client_cipher_count',
    'tls_client_extension_count', 'tls_client_alpn_info', 'tls_client_cipher_hash', 'tls_client_extension_hash',

    'tls_server_ptype', 'tls_server_version', 'tls_server_cipher_val', 'tls_server_extension_count',
    'tls_server_extension_hash', 'tls_server_alpn_info'
]

class FeatureMerger:
    def __init__(self):
        self.feature_template = {h: "" for h in HEADER}

    def merge_features(self, flow):
        all_features = self.feature_template.copy()
        
        all_features.update(extract_identification(flow))
        all_features.update(extract_transport(flow))
        all_features.update(extract_performance(flow))
        all_features.update(extract_application(flow))
        all_features.update(extract_security(flow))
        
        return all_features

    def get_feature_names(self):
        return HEADER