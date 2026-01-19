# config.py

import os
from dotenv import load_dotenv

load_dotenv()

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
VT_API_KEY = os.getenv("VT_API_KEY")
VIRUSSHARE_API_KEY = os.getenv("VIRUSSHARE_API_KEY")

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_API = "https://api.github.com"
GITHUB_SEARCH_API = "https://api.github.com/search/repositories"
VT_IP_API = "https://www.virustotal.com/api/v3/ip_addresses"
VT_DOMAIN_API = "https://www.virustotal.com/api/v3/domains"
VT_FILE_API = "https://www.virustotal.com/api/v3/files"

START_YEAR = 2023
END_YEAR = 2026
SEARCH_YEARS = [str(y) for y in range(START_YEAR, END_YEAR + 1)]
CVSS_THRESHOLD = 7.0
MAX_REPOS = 200

RESULT_DIR = "results"
CLONE_DIR = "./cloned_repos"

# Scan Options
SCAN_IP = False
SCAN_DOMAIN = False
SCAN_BINARY = True