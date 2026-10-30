# Recon Master Tool v1.0

Comprehensive Domain Reconnaissance Suite for authorized security testing.

## What it does

Finds all subdomains and determines which are active/live using 7 recon modules:

| Module | Technique | Output |
|--------|-----------|--------|
| 1. Passive Subdomain Enumeration | crt.sh, hackertarget, bufferover APIs | All discovered subdomains |
| 2. DNS Resolution | socket.gethostbyname | IP addresses per subdomain |
| 3. HTTP Probing | HTTP/HTTPS fetch + header/title/JS extraction | Active vs inactive hosts |
| 4. Port Scanning | TCP connect on common ports | Open ports per IP |
| 5. Directory Brute-Forcing | ~80 common paths (`/admin`, `/.env`, `/api`, etc.) | Exposed directories/files |
| 6. Parameter Fuzzing | ~40 params with XSS test payload | Reflected parameters |
| 7. JavaScript Extraction | `<script src>` parsing from live pages | All JS file URLs |

## Requirements

- Python 3.8+
- `requests`
- `urllib3`

## Installation

```bash
pip install -r requirements.txt
```

## Usage

```bash
python3 recon_master_tool.py
```

The tool runs interactively and will ask for:
- Target domain (e.g., `example.com`)
- HTTP timeout in seconds
- Concurrent thread count
- Output filename (JSON)
- Which optional modules to run (port scan, directory brute-force, parameter fuzz, JS extraction)

Results are saved to a JSON file with full details: subdomains, resolved IPs, probed hosts with status codes, detected bugs (CORS wildcard, missing security headers, etc.), open ports, directory hits, and parameter fuzzing findings.

## Example Output

```
[*] Target: example.com
[*] Timeout: 10s, Threads: 15

[*] Module 1: Passive Subdomain Enumeration
    [+] crt.sh: 42 subdomains
    [+] hackertarget: 15 subdomains
    [+] bufferover: 8 subdomains
    Total unique subdomains: 58

[*] Module 3: HTTP Probing
    [1/58] ✓ www.example.com (200) Active:True JS:12
    [2/58] ✗ api.example.com (403) Active:False JS:0

[*] Recon Summary
    Target domain       : example.com
    Subdomains found    : 58
    Resolved IPs        : 12
    Active/Live hosts   : 23
    ...
```

## ⚠️ Legal & Ethical Warning

**Only run this tool against domains you own or have explicit written authorization to test.**

Unauthorized scanning, reconnaissance, or vulnerability testing against third-party domains may violate:
- Computer fraud and abuse laws (CFAA in the US, equivalent laws elsewhere)
- Terms of service of the target domain
- Your local jurisdiction's cybersecurity regulations

The author is not responsible for any misuse of this tool. Use responsibly and only on authorized targets.

## Output Format

Results are saved as JSON with the following structure:

```json
{
  "target": "example.com",
  "subdomains": ["www.example.com", "api.example.com", ...],
  "resolved_ips": {"93.184.216.34": ["www.example.com"], ...},
  "unresolved": [],
  "results": [
    {
      "host": "www.example.com",
      "ip": "93.184.216.34",
      "scheme": "https",
      "status": 200,
      "active": true,
      "server": "nginx",
      "title": "Example Domain",
      "js_count": 5,
      "js_urls": ["https://www.example.com/app.js", ...],
      "security_headers": {...},
      "bugs": ["Missing security header: Content-Security-Policy"]
    }
  ],
  "active_hosts": [...],
  "js_files": [...],
  "port_scan": {...},
  "directory_bruteforce": {...},
  "parameter_fuzz": {...},
  "sources": [["crt.sh", 42], ["hackertarget", 15], ...]
}
```

## License

MIT License — for authorized educational and security research use only.
