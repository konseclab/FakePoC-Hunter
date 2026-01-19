# nvd.py
import requests
import time
import datetime
from config import NVD_API, START_YEAR, END_YEAR, CVSS_THRESHOLD

def fetch_high_cvss_cves():
    cves = []
    
    # NVD API 2.0 limitation: 120 days max range. We use 90 days to be safe.
    start_date = datetime.date(START_YEAR, 1, 1)
    end_date = datetime.date(END_YEAR, 12, 31)
    
    current_start = start_date
    
    while current_start <= end_date:
        current_end = current_start + datetime.timedelta(days=90)
        if current_end > end_date:
            current_end = end_date
            
        # Format dates as ISO 8601
        start_str = current_start.strftime("%Y-%m-%dT00:00:00.000")
        end_str = current_end.strftime("%Y-%m-%dT23:59:59.999")
        
        print(f"Fetching CVEs from {start_str} to {end_str}...")

        params = {
            "pubStartDate": start_str,
            "pubEndDate": end_str,
            "resultsPerPage": 2000
        }
        
        # Add User-Agent and use NVD recommended sleep
        headers = {
            "User-Agent": "PocHunter/1.0"
        }

        try:
            r = requests.get(NVD_API, params=params, headers=headers)
            r.raise_for_status()
            data = r.json()

            for item in data.get("vulnerabilities", []):
                cve = item["cve"]
                metrics = cve.get("metrics", {}).get("cvssMetricV31", [])

                if not metrics:
                    continue

                base_score = metrics[0]["cvssData"]["baseScore"]
                if base_score >= CVSS_THRESHOLD:
                    cves.append({
                        "cve_id": cve["id"],
                        "cvss": base_score,
                        "year": current_start.year # Approximate year
                    })
            
            # Move to next interval
            current_start = current_end + datetime.timedelta(days=1)
            
            # Sleep to avoid rate limiting (6 seconds recommended without API Key)
            time.sleep(6)
            
        except requests.exceptions.RequestException as e:
            print(f"Error fetching data: {e}")
            if hasattr(e, 'response') and e.response is not None:
                print(f"Response content: {e.response.text}")
            break
        except Exception as e:
            print(f"Unexpected error: {e}")
            break
            
    return cves

if __name__ == "__main__":
    cves = fetch_high_cvss_cves()
    print(f"Found {len(cves)} CVEs with CVSS >= {CVSS_THRESHOLD}")