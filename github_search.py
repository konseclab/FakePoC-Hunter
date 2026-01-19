# github_search.py
import requests
import time
from config import GITHUB_API, GITHUB_TOKEN, SEARCH_YEARS, MAX_REPOS

HEADERS = {"Authorization": f"Bearer {GITHUB_TOKEN}"}

def _make_github_request(url, params=None):
    """
    Helper function to make GitHub API requests with rate limit handling.
    """
    while True:
        try:
            r = requests.get(url, headers=HEADERS, params=params)
            
            if r.status_code in [403, 429]:
                # Check for rate limit
                remaining = r.headers.get("X-RateLimit-Remaining")
                if remaining is not None and int(remaining) == 0:
                    reset_time = int(r.headers.get("X-RateLimit-Reset", 0))
                    current_time = int(time.time())
                    sleep_time = reset_time - current_time + 10  # Add 10s buffer
                    
                    if sleep_time > 0:
                        print(f"Rate limit exceeded. Sleeping for {sleep_time} seconds until reset...")
                        time.sleep(sleep_time)
                        continue
            
            r.raise_for_status()
            return r.json()
            
        except requests.exceptions.RequestException as e:
            print(f"Error accessing GitHub API: {e}")
            raise e

def search_poc_repos():
    repos = []
    for year in SEARCH_YEARS:
        query = f"CVE-{year} poc language:Python"
        url = f"{GITHUB_API}/search/repositories"
        params = {"q": query, "per_page": 100}

        try:
            data = _make_github_request(url, params)
        except:
            continue
        
        if "items" not in data:
            continue

        for item in data["items"]:
            repos.append({
                "name": item["full_name"],
                "clone_url": item["clone_url"],
                "html_url": item["html_url"]
            })
            if len(repos) >= MAX_REPOS:
                return repos
    return repos

def search_repositories_by_cve(cve_id):
    """
    Search GitHub repositories for a specific CVE ID.
    Used by main.py. Fetches all pages (up to API limit of 1000 items).
    """
    repos = []
    query = f"{cve_id}"
    url = f"{GITHUB_API}/search/repositories"
    
    page = 1
    per_page = 100
    
    while True:
        params = {"q": query, "per_page": per_page, "page": page}

        try:
            data = _make_github_request(url, params)
        except:
            break

        if "items" not in data or not data["items"]:
            break

        for item in data["items"]:
            repos.append({
                "repo_name": item["full_name"],
                "clone_url": item["clone_url"],
                "html_url": item["html_url"]
            })
        
        # If we got fewer items than requested, we are on the last page
        if len(data["items"]) < per_page:
            break
            
        page += 1
        
        # Safety break for hard API limit (1000 items / 100 per page = 10 pages)
        if page > 10:
            break
    
    return repos

if __name__ == "__main__":
    # Test
    # print(search_repositories_by_cve("CVE-2024-0001"))
    pass
