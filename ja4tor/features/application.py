import hashlib
from scapy.all import Raw, load_layer
from scapy.layers.tls.handshake import TLSClientHello
from scapy.layers.tls.extensions import ServerName

load_layer("tls")

def _sha256_hash(data_list, length=12):
    if not data_list:
        return '0' * length
    str_list = [str(item) for item in data_list]
    str_list.sort()
    return hashlib.sha256(",".join(str_list).encode()).hexdigest()[:length]

def _calculate_http_client_fingerprint(pkt_pyshark):
    if 'HTTP' not in pkt_pyshark:
        return {}
        
    try:
        http = pkt_pyshark.http
        method = (getattr(http, "request_method", "") or "").lower()[:2]
        version = "20" if str(pkt_pyshark.highest_layer) == "HTTP2" else "11"
        has_cookie = 'c' if hasattr(http, 'cookie') else 'n'
        has_referer = 'r' if hasattr(http, 'referer') else 'n'
        
        headers = []
        for field in dir(http):
            if field.endswith('_header'):
                header_name = field.rsplit('_header', 1)[0].lower()
                if header_name not in ['cookie', 'referer']:
                    headers.append(header_name)
        
        header_len = f"{min(len(headers), 99):02d}"
        header_hash = _sha256_hash(headers)
        has_lang = "l1" if hasattr(http, 'accept_language') else "l0"
        
        cookie_fields = []
        if hasattr(http, 'cookie'):
            try:
                cookie_str = http.cookie
                if isinstance(cookie_str, list): cookie_str = '; '.join(cookie_str)
                parts = cookie_str.split(';')
                cookie_fields = sorted([p.split('=')[0].strip() for p in parts if '=' in p])
            except Exception:
                cookie_fields = []
        cookie_hash = _sha256_hash(cookie_fields)

        return {
            "http_req_method_short": method,
            "http_req_version": version,
            "http_req_has_cookie": has_cookie,
            "http_req_has_referer": has_referer,
            "http_req_header_count": header_len,
            "http_req_has_lang": has_lang,
            "http_req_header_hash": header_hash,
            "http_req_cookie_hash": cookie_hash,
        }
    except Exception:
        return {}

def _extract_tls_sni_domain(pkt_scapy):
    if pkt_scapy and pkt_scapy.haslayer(TLSClientHello):
        client_hello = pkt_scapy.getlayer(TLSClientHello)
        if client_hello and hasattr(client_hello, 'extensions') and client_hello.extensions:
            try:
                for ext in client_hello.extensions:
                    if ext.type == 0:
                        if hasattr(ext, 'servernames'):
                            return ext.servernames[0].servername.decode('utf-8', 'ignore')
            except Exception:
                pass
    return ""

def _hash_str_safe(s, n=16):
    if not s:
        return ""
    return hashlib.md5(str(s).encode()).hexdigest()[:n]

def extract_application(flow):
    app_features = {
        "http_method": "", "http_host_hash": "", "http_user_agent_hash": "",
        "http_path_len": 0, "tls_sni_domain": "", "http_req_method_short": "",
        "http_req_version": "", "http_req_has_cookie": "", "http_req_has_referer": "",
        "http_req_header_count": "", "http_req_has_lang": "", "http_req_header_hash": "",
        "http_req_cookie_hash": "",
    }
    http_info_extracted = False
    sni_domain_found = False

    for p in flow.packets:
        pkt_pyshark = p.get("pyshark_pkt")
        pkt_scapy = p.get("scapy_pkt")

        if not http_info_extracted and pkt_pyshark and 'HTTP' in pkt_pyshark:
            try:
                http = pkt_pyshark.http
                app_features["http_method"] = getattr(http, "request_method", "")
                app_features["http_host_hash"] = _hash_str_safe(getattr(http, "host", ""))
                app_features["http_user_agent_hash"] = _hash_str_safe(getattr(http, "user_agent", ""))
                uri = getattr(http, "request_uri", "")
                app_features["http_path_len"] = len(str(uri)) if uri else 0
                
                http_details = _calculate_http_client_fingerprint(pkt_pyshark)
                app_features.update(http_details)
                http_info_extracted = True
            except (AttributeError, KeyError):
                continue

        if not sni_domain_found and pkt_scapy:
            sni_domain = _extract_tls_sni_domain(pkt_scapy)
            if sni_domain:
                app_features["tls_sni_domain"] = sni_domain
                sni_domain_found = True
        
        if http_info_extracted and sni_domain_found:
            break
            
    return app_features