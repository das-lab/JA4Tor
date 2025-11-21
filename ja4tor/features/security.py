import hashlib
from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
from scapy.all import load_layer

load_layer("tls")
GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
}

def _sha256_hash(data_list, length=12):
    if not data_list:
        return '0' * length
    str_list = [str(item) for item in data_list]
    str_list.sort()
    return hashlib.sha256(",".join(str_list).encode()).hexdigest()[:length]

def _calculate_tls_client_fingerprint(pkt_scapy):
    if not pkt_scapy.haslayer(TLSClientHello): return {}
    
    client_hello = pkt_scapy.getlayer(TLSClientHello)
    if not client_hello: return {}
    
    ptype = 't'
    version = f"0x{client_hello.version:04x}" if client_hello.version is not None else ""

    extensions_list = getattr(client_hello, 'extensions', None) or []
    
    sni_present = any(ext.type == 0 for ext in extensions_list)
    sni = 'd' if sni_present else 'i'
    
    ciphers = [c for c in client_hello.ciphers if c not in GREASE_TABLE] if client_hello.ciphers else []
    cipher_len = f"{min(len(ciphers), 99):02d}"
    cipher_hash = _sha256_hash(ciphers)
    
    extensions_types = [e.type for e in extensions_list if e.type not in GREASE_TABLE]
    ext_len = f"{min(len(extensions_types), 99):02d}"
    ext_hash = _sha256_hash(extensions_types)
    
    alpn_present = any(ext.type == 16 for ext in extensions_list)
    alpn_info = "a1" if alpn_present else "a0"
    
    return {
        "tls_client_ptype": ptype, "tls_client_version": version, "tls_client_sni_presence": sni,
        "tls_client_cipher_count": cipher_len, "tls_client_extension_count": ext_len,
        "tls_client_alpn_info": alpn_info, "tls_client_cipher_hash": cipher_hash,
        "tls_client_extension_hash": ext_hash,
    }

def _calculate_tls_server_fingerprint(pkt_scapy):
    if not pkt_scapy.haslayer(TLSServerHello): return {}
    
    server_hello = pkt_scapy.getlayer(TLSServerHello)
    if not server_hello: return {}
    
    ptype = 't'
    version = f"0x{server_hello.version:04x}" if server_hello.version is not None else ""
    
    # TLSServerHello may not have a cipher attribute in some cases
    cipher_val = f"{server_hello.cipher:04x}" if hasattr(server_hello, 'cipher') and server_hello.cipher is not None else ""
    
    extensions_list = getattr(server_hello, 'extensions', None) or []

    extensions_types = [e.type for e in extensions_list if e.type not in GREASE_TABLE]
    ext_len = f"{min(len(extensions_types), 99):02d}"
    ext_hash = _sha256_hash(extensions_types)
    
    alpn_present = any(ext.type == 16 for ext in extensions_list)
    alpn_info = "a1" if alpn_present else "a0"
    
    return {
        "tls_server_ptype": ptype, "tls_server_version": version, "tls_server_cipher_val": cipher_val,
        "tls_server_extension_count": ext_len, "tls_server_extension_hash": ext_hash,
        "tls_server_alpn_info": alpn_info,
    }

def extract_security(flow):
    all_security_features = {
        'tls_client_ptype': '', 'tls_client_version': '', 'tls_client_sni_presence': '', 
        'tls_client_cipher_count': '', 'tls_client_extension_count': '', 
        'tls_client_alpn_info': '', 'tls_client_cipher_hash': '', 'tls_client_extension_hash': '',
        'tls_server_ptype': '', 'tls_server_version': '', 'tls_server_cipher_val': '',
        'tls_server_extension_count': '', 'tls_server_extension_hash': '', 'tls_server_alpn_info': '',
    }
    client_features_found = False
    server_features_found = False

    for p in flow.packets:
        pkt_scapy = p.get("scapy_pkt")
        if not pkt_scapy: continue

        if not client_features_found and pkt_scapy.haslayer(TLSClientHello):
            client_features = _calculate_tls_client_fingerprint(pkt_scapy)
            if client_features:
                all_security_features.update(client_features)
                client_features_found = True
        
        if not server_features_found and pkt_scapy.haslayer(TLSServerHello):
            server_features = _calculate_tls_server_fingerprint(pkt_scapy)
            if server_features:
                all_security_features.update(server_features)
                server_features_found = True
        
        if client_features_found and server_features_found:
            break

    return all_security_features