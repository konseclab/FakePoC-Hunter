import os
import sys
import requests
import json
import csv
from nvd import fetch_high_cvss_cves
from github_search import search_repositories_by_cve
from static_analysis import extract_indicators
from virustotal import check_ip, check_domain, check_file_hash
from repo_manager import clone_repo, delete_repo, walk_repo_files
from config import CLONE_DIR, SCAN_IP, SCAN_DOMAIN, SCAN_BINARY, VIRUSSHARE_API_KEY, RESULT_DIR
from virusshareclient import VirusShareClient, VirusShareAPIError

def save_results(results):
    os.makedirs(RESULT_DIR, exist_ok=True)
    
    with open(f"{RESULT_DIR}/results.json", "w") as f:
        json.dump(results, f, indent=2)

    if results:
        with open(f"{RESULT_DIR}/results.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)

def main():
    results = []
    
    # Load existing results if available
    results_file = os.path.join(RESULT_DIR, "results.json")
    if os.path.exists(results_file):
        try:
            with open(results_file, "r") as f:
                content = f.read()
                if content:
                    results = json.loads(content)
            print(f"[*] Loaded {len(results)} existing results.")
        except Exception as e:
            print(f"[!] Failed to load existing results: {e}")
    
    # Initialize VirusShare Client
    vs_client = VirusShareClient(api_key=VIRUSSHARE_API_KEY)

    # Load previously scanned repositories
    scanned_repos_file = os.path.join(RESULT_DIR, "scanned_repos.txt")
    scanned_repos = set()
    if os.path.exists(scanned_repos_file):
        try:
            with open(scanned_repos_file, "r") as f:
                scanned_repos = set(line.strip() for line in f if line.strip())
            print(f"[*] Loaded {len(scanned_repos)} previously scanned repositories.")
        except Exception as e:
            print(f"[!] varied to load scanned repos: {e}")
    
    print("[*] Fetching High CVSS CVEs from NVD...")
    cves = fetch_high_cvss_cves()
    
    total_cves = len(cves)
    print(f"[*] Found {total_cves} CVEs to process.")

    for i, cve in enumerate(cves, 1):
        cve_id = cve["cve_id"]
        
        # Use \r to overwrite line for progress, preventing flood
        sys.stdout.write(f"\r[*] [{i}/{total_cves}] Checking {cve_id}... ")
        sys.stdout.flush()
        
        try:
            repos = search_repositories_by_cve(cve_id)
        except Exception as e:
            continue

        if not repos:
            continue
            
        sys.stdout.write(f"\n[+] Found {len(repos)} repositories for {cve_id}\n")

        for repo in repos:
            repo_name = repo['repo_name']
            
            if repo_name in scanned_repos:
                print(f"  [!] Skipping {repo_name} (already scanned)")
                continue

            repo_url = repo['clone_url']
            repo_dir = os.path.join(CLONE_DIR, repo_name.replace("/", "_"))
            
            print(f"  -> Scanning {repo_name}...")
            
            try:
                if not clone_repo(repo_url, repo_dir):
                    print(f"  [!] Failed to clone {repo_name}")
                    continue
            
                found_in_repo = False
                
                # Scan all files in the repo
                for file_path, is_binary, content_or_hash in walk_repo_files(repo_dir):
                    
                    if is_binary and SCAN_BINARY:
                        # Binary File: Check Hash against VirusShare instead of VirusTotal
                        file_hash = content_or_hash
                        try:
                            # Use VirusShare Client
                            print(f"    [?] Checking binary with VirusShare: {os.path.basename(file_path)}")
                            vs_report = vs_client.get_file_report(file_hash)
                            
                            # Check maliciousness based on customized detector
                            if vs_report and vs_report.get("virustotal", {}).get("positives", 0) > 0:
                                print(f"    [!] MALICIOUS BINARY FOUND (VirusShare): {os.path.basename(file_path)}")
                                results.append({
                                    "cve": cve_id,
                                    "repo": repo_name,
                                    "file": file_path,
                                    "indicator": file_hash,
                                    "type": "hash",
                                    "vt": vs_report.get("virustotal", {}) # Store VT part separately or full report? 
                                    # Existing code expects 'vt' key to be something that can be saved/displayed.
                                    # Let's store full report as 'vt' (which is now confusingly named, maybe rename key later but for compatibility keep 'vt' or 'raw_data')
                                    # Or better, store 'vs_report' and adapt output.py?
                                    # User didn't ask to change output format. `results` list is passed to `save_results`.
                                })
                                save_results(results)
                                found_in_repo = True
                                
                        except VirusShareAPIError as e:
                            # Handle "File not found" or rate limits without crashing entire scan
                            # print(f"    [!] VirusShare Error: {e}") 
                            pass
                        except Exception as e:
                            print(f"    [!] Unexpected VirusShare Error: {e}")
                            
                            print(f"    [!] Unexpected VirusShare Error: {e}")
                            
                    elif not is_binary:
                        # Text File: Static Analysis
                        content = content_or_hash
                        ips, domains = extract_indicators(content)
                        
                        if SCAN_IP:
                            for ip in ips:
                                vt = check_ip(ip)
                                if vt and (vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0):
                                    print(f"    [!] MALICIOUS IP FOUND: {ip} in {file_path}")
                                    results.append({
                                        "cve": cve_id,
                                        "repo": repo_name,
                                        "file": file_path,
                                        "indicator": ip,
                                        "type": "ip",
                                        "vt": vt
                                    })
                                    save_results(results)
                                    found_in_repo = True

                        if SCAN_DOMAIN:
                            for domain in domains:
                                vt = check_domain(domain)
                                if vt and (vt.get("malicious", 0) > 0 or vt.get("suspicious", 0) > 0):
                                    print(f"    [!] MALICIOUS DOMAIN FOUND: {domain} in {file_path}")
                                    results.append({
                                        "cve": cve_id,
                                        "repo": repo_name,
                                        "file": file_path,
                                        "indicator": domain,
                                        "type": "domain",
                                        "vt": vt
                                    })
                                    save_results(results)
                                    found_in_repo = True
                
                if found_in_repo:
                     print(f"  [!!!] Malicious indicators confirmed in {repo_name}")
                    
            except KeyboardInterrupt:
                print(f"\n  [!] Interrupted while scanning {repo_name}. Cleaning up...")
                raise # Re-raise to be caught by main handler
            except Exception as e:
                print(f"  [!] Error analyzing {repo_name}: {e}")
            finally:
                # Cleanup
                delete_repo(repo_dir)
                
                # Mark as scanned
                with open(scanned_repos_file, "a") as f:
                    f.write(repo_name + "\n")
                scanned_repos.add(repo_name)

    sys.stdout.write("\n") # Done
    if results:
        print(f"[*] Analysis complete. Found malicious indicators in {len(results)} instances.")
        save_results(results)
    else:
        print("[*] Analysis complete. No malicious indicators found.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[!] Execution interrupted by user. Exiting...")
        sys.exit(0)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
