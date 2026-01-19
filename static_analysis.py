# static_analysis.py
import re
import base64
import binascii
import ipaddress

IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_REGEX = re.compile(r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
BASE64_REGEX = re.compile(r'[a-zA-Z0-9+/=]{8,}')

IGNORED_EXTENSIONS = {'.png', '.jpg', '.jpeg', '.gif', '.css', '.js', '.html', '.xml', '.json', '.py', '.c', '.cpp', '.h', '.java', '.go', '.rs', '.php'}
IGNORED_DOMAINS = {'localhost', 'example.com', 'test.com', 'google.com', 'github.com', 'pypi.org', 'herokuapp.com'}

def is_public_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or str(ip) == "0.0.0.0")
    except ValueError:
        return False

def is_interesting_domain(domain):
    domain = domain.lower()
    if domain in IGNORED_DOMAINS:
        return False
    
    # Simple check to avoid file extensions matching as domains (e.g., style.css)
    # This is a heuristic: if the TLD part is a common file extension, ignore it.
    if any(domain.endswith(ext) for ext in IGNORED_EXTENSIONS):
        return False
        
    return True

def extract_from_text(text):
    """Helper to extract IPs and domains from a single text block."""
    raw_ips = set(IP_REGEX.findall(text))
    raw_domains = set(DOMAIN_REGEX.findall(text))
    
    # Filter IPs
    filtered_ips = set()
    for ip in raw_ips:
        if is_public_ip(ip):
            filtered_ips.add(ip)
            
    # Filter Domains
    filtered_domains = set()
    for d in raw_domains:
        if is_interesting_domain(d):
            filtered_domains.add(d)
            
    return filtered_ips, filtered_domains

def extract_indicators(text):
    """
    Extracts IPs and domains from text, including those hidden within Base64 strings.
    Filters private IPs and uninteresting domains.
    """
    all_ips = set()
    all_domains = set()

    # 1. Inspect original text
    ips, domains = extract_from_text(text)
    all_ips.update(ips)
    all_domains.update(domains)

    # 2. Find and inspect Base64 strings
    for b64_match in BASE64_REGEX.findall(text):
        try:
            # Add padding if missing
            padding = len(b64_match) % 4
            if padding:
                b64_match += '=' * (4 - padding)
            
            decoded_bytes = base64.b64decode(b64_match, validate=True)
            
            # We only care if it decodes to UTF-8 text
            decoded_text = decoded_bytes.decode('utf-8')
            
            # Recursive extraction on decoded content
            d_ips, d_domains = extract_from_text(decoded_text)
            
            if d_ips or d_domains:
                # print(f"DEBUG: Found hidden indicators in Base64: {b64_match} -> {decoded_text}")
                pass
                
            all_ips.update(d_ips)
            all_domains.update(d_domains)
            
        except (binascii.Error, UnicodeDecodeError):
            continue

    return list(all_ips), list(all_domains)
