# behaviors.py
import re

# Regex patterns for malicious behaviors

# Exfiltration (Sending data out)
EXFILTRATION_PATTERNS = [
    (re.compile(r"requests\.post\("), "Sending HTTP POST request (potential exfiltration)"),
    (re.compile(r"requests\.put\("), "Sending HTTP PUT request"),
    (re.compile(r"urllib\.request\.urlopen\("), "Opening URL (potential connection)"),
    (re.compile(r"socket\.socket\("), "Raw socket usage (potential reverse shell/connect)"),
    (re.compile(r"smtplib\.SMTP"), "Sending email (potential data theft)"),
    (re.compile(r"ftplib\.FTP"), "FTP usage (potential file upload)"),
    (re.compile(r"telebot|discord_webhook"), "Bot API usage (C2 communication)"),
    (re.compile(r"upload_file|send_document"), "Explicit file upload keywords"),
]

# Downloading/Dropping (Getting payload)
DOWNLOAD_PATTERNS = [
    (re.compile(r"requests\.get\("), "Sending HTTP GET request (potential download)"),
    (re.compile(r"urlretrieve\("), "Downloading file via urllib"),
    (re.compile(r"wget |curl "), "Command line download tool usage"),
    (re.compile(r"powershell.*DownloadFile"), "PowerShell download"),
    (re.compile(r"bitsadmin"), "BITSAdmin usage (Windows downloader)"),
    (re.compile(r"certutil"), "CertUtil usage (Windows downloader)"),
]

# Execution (Running code/commands)
EXECUTION_PATTERNS = [
    (re.compile(r"os\.system\("), "Executing system command"),
    (re.compile(r"subprocess\.Popen|subprocess\.run|subprocess\.call"), "Executing subprocess"),
    (re.compile(r"exec\("), "Dynamic code execution"),
    (re.compile(r"eval\("), "Dynamic code evaluation"),
    (re.compile(r"os\.popen\("), "Opening pipe to command"),
]

# Obfuscation (Hiding intent)
OBFUSCATION_PATTERNS = [
    (re.compile(r"base64\.b64decode"), "Base64 decoding"),
    (re.compile(r"codecs\.decode.*rot13"), "ROT13 decoding"),
    (re.compile(r"zlib\.decompress"), "Zlib decompression (potential payload extraction)"),
    (re.compile(r"fernet|AES"), "Encryption usage"),
]

def analyze_file_content(content):
    """
    Scans file content for malicious behaviors.
    Returns a list of matched behavior descriptions.
    """
    detected_behaviors = []
    
    # Check all categories
    for category in [EXFILTRATION_PATTERNS, DOWNLOAD_PATTERNS, EXECUTION_PATTERNS, OBFUSCATION_PATTERNS]:
        for pattern, desc in category:
            if pattern.search(content):
                detected_behaviors.append(desc)
                
    return list(set(detected_behaviors)) # Deduplicate
