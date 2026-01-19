# deep_scan.py
import json
import os
import sys
from config import RESULT_DIR, CLONE_DIR
from repo_manager import clone_repo, delete_repo, get_all_file_contents
from behaviors import analyze_file_content

def load_initial_results():
    results_path = os.path.join(RESULT_DIR, "results.json")
    if not os.path.exists(results_path):
        print(f"[!] Results file not found: {results_path}")
        return []
    
    try:
        with open(results_path, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print("[!] Failed to decode results.json")
        return []

def main():
    print("[*] Starting Deep Behavioral Analysis...")
    initial_results = load_initial_results()
    
    if not initial_results:
        print("[-] No initial results to analyze.")
        return

    # Deduplicate repos
    # We want to scan each repo only once, even if it had multiple malicious IPs
    target_repos = {}
    for item in initial_results:
        repo_name = item.get("repo") or item.get("repo_name")
        if repo_name:
            target_repos[repo_name] = item.get("repo_url") or f"https://github.com/{repo_name}.git"

    print(f"[*] Identified {len(target_repos)} unique repositories for deep scan.")

    deep_findings = []

    for i, (repo_name, repo_url) in enumerate(target_repos.items(), 1):
        print(f"[{i}/{len(target_repos)}] Deep scanning {repo_name}...")
        
        repo_dir = os.path.join(CLONE_DIR, repo_name.replace("/", "_"))
        
        if not clone_repo(repo_url, repo_dir):
            print(f"  [!] Failed to clone {repo_name}")
            continue
            
        repo_behaviors = []
        
        try:
            for file_path, content in get_all_file_contents(repo_dir):
                behaviors = analyze_file_content(content)
                if behaviors:
                    for b in behaviors:
                        print(f"    [!] DETECTED: {b} in {os.path.basename(file_path)}")
                        repo_behaviors.append({
                            "file": file_path,
                            "behavior": b
                        })
            
            if repo_behaviors:
                deep_findings.append({
                    "repo": repo_name,
                    "url": repo_url,
                    "findings": repo_behaviors
                })
                
        finally:
            delete_repo(repo_dir)

    # Save output
    output_path = os.path.join(RESULT_DIR, "deep_analysis_results.json")
    with open(output_path, "w") as f:
        json.dump(deep_findings, f, indent=2)
        
    print(f"\n[*] Deep analysis complete. Found suspicious behaviors in {len(deep_findings)} repositories.")
    print(f"[*] Results saved to {output_path}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Analysis interrupted.")
        sys.exit(0)
