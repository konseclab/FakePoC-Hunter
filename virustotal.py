# virustotal.py
import requests
import time
import sys
from config import VT_API_KEY, VT_IP_API, VT_DOMAIN_API, VT_FILE_API

CONSECUTIVE_ERRORS = 0

HEADERS = {"x-apikey": VT_API_KEY}

def _make_request(url):
    """
    Helper function to make requests with rate limit handling (429).
    """
    global CONSECUTIVE_ERRORS
    while True:
        try:
            # Timeout set to 10 seconds
            r = requests.get(url, headers=HEADERS, timeout=10)
            
            if r.status_code == 429:
                print("VirusTotal rate limit exceeded. Sleeping for 60 seconds...")
                CONSECUTIVE_ERRORS += 1
                if CONSECUTIVE_ERRORS >= 3:
                    print("[!!!] 3 consecutive 429 errors from VirusTotal. Exiting...")
                    sys.exit(1)
                
                time.sleep(60)
                continue
            
            # Reset counter on non-429 response
            CONSECUTIVE_ERRORS = 0
            
            if r.status_code == 404:
                return None # Not found in VT
            
            if r.status_code != 200:
                return None
                
            return r.json()["data"]["attributes"]["last_analysis_stats"]
            
        except requests.exceptions.RequestException as e:
            print(f"Error accessing VirusTotal: {e}")
            # Reset counter on other exceptions? Or keep it? 
            # If we want strictly "consecutive 429s", an exception (like timeout) breaks the streak of *received* 429s?
            # Or does it? If I get 429, Timeout, 429... technically not consecutive 429s.
            # I will reset it to be safe.
            CONSECUTIVE_ERRORS = 0
            return None

def check_ip(ip):
    url = f"{VT_IP_API}/{ip}"
    return _make_request(url)

def check_domain(domain):
    url = f"{VT_DOMAIN_API}/{domain}"
    return _make_request(url)

def check_file_hash(file_hash):
    """
    Checks a file hash (SHA-256, MD5, SHA-1) against VirusTotal.
    """
    url = f"{VT_FILE_API}/{file_hash}"
    return _make_request(url)
