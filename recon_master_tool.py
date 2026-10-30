#!/usr/bin/env python3
"""
RECON MASTER TOOL v1.0
Comprehensive Domain Reconnaissance Suite

Finds all subdomains and determines which are active/live using multiple
passive and active reconnaissance techniques.

WARNING: Only run against targets you own or have explicit written
authorization to test. Unauthorized scanning may violate laws and ToS.
"""

import json
import os
import re
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    END = "\033[0m"


def banner():
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("=" * 70)
    print("  RECON MASTER TOOL v1.0")
    print("  Comprehensive Domain Reconnaissance Suite")
    print("  Subdomain Discovery -> Resolution -> Active Host Detection")
    print("=" * 70)
    print(f"{Colors.YELLOW}  [WARNING] Authorized use only!{Colors.END}")
    print(f"{Colors.YELLOW}  Only scan domains you own or have written permission to test.{Colors.END}")
    print("=" * 70)
    print(f"{Colors.END}")


def ask(prompt, default=None, required=False, choices=None):
    while True:
        if default:
            p = f"{Colors.BLUE}{prompt} [{default}]: {Colors.END}"
        else:
            p = f"{Colors.BLUE}{prompt}: {Colors.END}"
        val = input(p).strip()
        if not val:
            if default is not None:
                return default
            if required:
                print(f"{Colors.RED}  [!] This field is required.{Colors.END}")
                continue
            return ""
        if choices and val not in choices:
            print(f"{Colors.RED}  [!] Choose from: {', '.join(choices)}{Colors.END}")
            continue
        return val


def ask_int(prompt, default=None, required=False):
    while True:
        val = ask(prompt, default=default, required=required)
        if val == "" and not required:
            return None
        try:
            return int(val)
        except ValueError:
            print(f"{Colors.RED}  [!] Please enter a valid integer.{Colors.END}")


# =============================================================================
# MODULE 1: PASSIVE SUBDOMAIN ENUMERATION
# =============================================================================

def enumerate_subdomains_crtsh(domain, quiet=False):
    """crt.sh certificate transparency log enumeration."""
    subs = set()
    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=20, verify=False)
        if r.status_code == 200:
            data = r.json()
            for entry in data:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower()
                    if line and line.endswith(f".{domain}"):
                        subs.add(line)
    except Exception as e:
        if not quiet:
            print(f"  {Colors.RED}[-] crt.sh error: {e}{Colors.END}")
    return subs


def enumerate_subdomains_hackertarget(domain, quiet=False):
    """HackerTarget hostsearch API enumeration."""
    subs = set()
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, verify=False)
        if r.status_code == 200:
            for line in r.text.strip().split("\n")[1:]:
                parts = line.split(",")
                if len(parts) == 2:
                    subs.add(parts[0].strip().lower())
    except Exception as e:
        if not quiet:
            print(f"  {Colors.RED}[-] hackertarget error: {e}{Colors.END}")
    return subs


def enumerate_subdomains_bufferover(domain, quiet=False):
    """Bufferover DNS API enumeration."""
    subs = set()
    try:
        url = f"https://api.bufferover.run/dns?q=.{domain}"
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=15, verify=False)
        if r.status_code == 200:
            data = r.json()
            for d in data:
                name = d.get("name", "")
                if name.endswith(f".{domain}"):
                    subs.add(name.lower())
    except Exception as e:
        if not quiet:
            print(f"  {Colors.RED}[-] bufferover error: {e}{Colors.END}")
    return subs


def enumerate_subdomains(domain, quiet=False):
    """Run all passive enumeration sources and merge results."""
    all_subs = set()
    sources = []

    if not quiet:
        print(f"\n{Colors.BOLD}[*] Module 1: Passive Subdomain Enumeration{Colors.END}")

    s1 = enumerate_subdomains_crtsh(domain, quiet)
    all_subs.update(s1)
    sources.append(("crt.sh", len(s1)))

    s2 = enumerate_subdomains_hackertarget(domain, quiet)
    all_subs.update(s2)
    sources.append(("hackertarget", len(s2)))

    s3 = enumerate_subdomains_bufferover(domain, quiet)
    all_subs.update(s3)
    sources.append(("bufferover", len(s3)))

    if not quiet:
        for src, cnt in sources:
            print(f"    {Colors.GREEN}[+]{Colors.END} {src}: {cnt} subdomains")
        print(f"    {Colors.BOLD}Total unique subdomains: {len(all_subs)}{Colors.END}")

    return sorted(all_subs), sources


# =============================================================================
# MODULE 2: DNS RESOLUTION
# =============================================================================

def resolve_subdomains(subs, quiet=False):
    """Resolve each subdomain to its IP address(es)."""
    resolved = {}
    unresolved = []

    def resolve(sub):
        try:
            ip = socket.gethostbyname(sub)
            return sub, ip, None
        except Exception as e:
            return sub, None, str(e)

    if not quiet:
        print(f"\n{Colors.BOLD}[*] Module 2: DNS Resolution{Colors.END}")

    with ThreadPoolExecutor(max_workers=30) as ex:
        futures = {ex.submit(resolve, s): s for s in subs}
        for fut in as_completed(futures):
            sub, ip, err = fut.result()
            if ip:
                resolved.setdefault(ip, []).append(sub)
            else:
                unresolved.append(sub)

    if not quiet:
        print(f"    {Colors.GREEN}[+]{Colors.END} Resolved: {len(subs) - len(unresolved)}/{len(subs)}")
        print(f"    {Colors.GREEN}[+]{Colors.END} Unique IPs: {len(resolved)}")
        if unresolved:
            print(f"    {Colors.YELLOW}[!]{Colors.END} Unresolved: {len(unresolved)}")

    return resolved, unresolved


# =============================================================================
# MODULE 3: HTTP PROBING (ACTIVE vs INACTIVE)
# =============================================================================

def probe_site(sub, timeout=10):
    """Probe a subdomain over HTTP/HTTPS to check if it's active."""
    result = {
        "host": sub,
        "ip": "",
        "scheme": "",
        "status": 0,
        "server": "",
        "title": "",
        "content_length": 0,
        "js_count": 0,
        "js_urls": [],
        "css_count": 0,
        "headers": {},
        "security_headers": {},
        "bugs": [],
        "error": "",
        "active": False,
    }

    try:
        result["ip"] = socket.gethostbyname(sub)
    except Exception:
        pass

    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{sub}",
                timeout=timeout,
                allow_redirects=True,
                verify=False,
                headers={"User-Agent": "Mozilla/5.0 (compatible; recon-master/1.0)"},
            )
            result["scheme"] = scheme
            result["status"] = resp.status_code
            result["active"] = resp.status_code < 500  # consider anything < 500 as active
            result["server"] = resp.headers.get("Server", "")
            result["content_length"] = len(resp.content)
            result["headers"] = dict(resp.headers)

            m = re.search(r"<title>(.*?)</title>", resp.text, re.IGNORECASE | re.DOTALL)
            result["title"] = m.group(1).strip()[:100] if m else ""

            js_urls = re.findall(r'<script[^>]*src=["\']([^"\']+)["\']', resp.text)
            result["js_count"] = len(js_urls)
            for src in js_urls:
                full = src if src.startswith("http") else f"{scheme}://{sub}{src}"
                result["js_urls"].append(full)

            css_urls = re.findall(r'<link[^>]*href=["\']([^"\']+\.css[^"\']*)["\']', resp.text)
            result["css_count"] = len(css_urls)

            for h in ["X-Frame-Options", "X-Content-Type-Options",
                        "Strict-Transport-Security", "Content-Security-Policy"]:
                result["security_headers"][h] = resp.headers.get(h, "MISSING")

            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            if acao == "*":
                result["bugs"].append("CORS wildcard (*)")
            elif acao and resp.status_code == 200:
                result["bugs"].append(f"CORS reflect: {acao}")

            for h in ["X-Frame-Options", "X-Content-Type-Options",
                        "Strict-Transport-Security", "Content-Security-Policy"]:
                if h not in resp.headers:
                    result["bugs"].append(f"Missing security header: {h}")

            if resp.headers.get("X-Powered-By"):
                result["bugs"].append(f"Technology leak: X-Powered-By {resp.headers['X-Powered-By']}")

            inline = re.findall(r"<script[^>]*>(.*?)</script>", resp.text, re.DOTALL)
            for s in inline:
                if re.search(r"password|secret|api_key|token|bearer|AKIA|sk-", s, re.IGNORECASE):
                    result["bugs"].append("Possible secrets in inline script")
                    break

            break
        except Exception:
            continue

    return result


def probe_all(subs, timeout=10, max_workers=15, quiet=False):
    """Probe all subdomains to find which are active/live."""
    results = []
    all_subs = sorted(subs)

    if not quiet:
        print(f"\n{Colors.BOLD}[*] Module 3: HTTP Probing (Active Host Detection){Colors.END}")

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(probe_site, s, timeout): s for s in all_subs}
        for i, fut in enumerate(as_completed(futures), 1):
            r = fut.result()
            results.append(r)
            icon = f"{Colors.GREEN}✓{Colors.END}" if r["active"] else f"{Colors.RED}✗{Colors.END}"
            bugs = f" | bugs: {r['bugs']}" if r["bugs"] else ""
            print(f"    [{i}/{len(all_subs)}] {icon} {r['host']} "
                  f"({r['status']}) Active:{r['active']} JS:{r['js_count']}{bugs}")

    active = [r for r in results if r["active"]]
    inactive = [r for r in results if not r["active"]]
    if not quiet:
        print(f"\n    {Colors.GREEN}[+]{Colors.END} Active/Live hosts: {len(active)}/{len(results)}")
        print(f"    {Colors.RED}[-]{Colors.END} Inactive/Dead hosts: {len(inactive)}/{len(results)}")

    return results


# =============================================================================
# MODULE 4: PORT SCANNING
# =============================================================================

def scan_ports(host, ports=None, timeout=2, quiet=False):
    """Scan common TCP ports on a host."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 27017]
    open_ports = []

    def check_port(port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                if s.connect_ex((host, port)) == 0:
                    return port
        except Exception:
            pass
        return None

    if not quiet:
        print(f"\n{Colors.BOLD}[*] Module 4: Port Scanning{Colors.END}")

    with ThreadPoolExecutor(max_workers=min(50, len(ports))) as ex:
        futures = {ex.submit(check_port, p): p for p in ports}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                open_ports.append(r)

    if not quiet:
        print(f"    {Colors.GREEN}[+]{Colors.END} {host}: {len(open_ports)} open ports -> {sorted(open_ports)}")

    return sorted(open_ports)


# =============================================================================
# MODULE 5: DIRECTORY BRUTE-FORCING
# =============================================================================

def brute_force_dirs(base_url, timeout=10, quiet=False):
    """Brute-force common directories/files on a web server."""
    wordlist = [
        "admin", "administrator", "login", "wp-admin", "wp-login", "config",
        ".env", ".git", ".svn", ".htaccess", "robots.txt", "sitemap.xml",
        "backup", "backups", "db", "database", "test", "dev", "staging",
        "api", "api/v1", "api/v2", "graphql", "swagger", "openapi.json",
        "docs", "documentation", "phpmyadmin", "manager", "console",
        "shell", "cgi-bin", "server-status", ".well-known", "upload",
        "uploads", "files", "assets", "static", "media", "images",
        "install", "setup", "config.php", "web.config", "package.json",
        ".DS_Store", "package-lock.json", "composer.json", "Gemfile",
        "Dockerfile", "docker-compose.yml", ".git/config", ".env.bak",
        "web.config.bak", "config.bak", "db.sql", "backup.zip", "backup.tar.gz",
        ".ssh", "id_rsa", "authorized_keys", "credentials", "secrets",
        "health", "healthz", "ping", "status", "metrics", "version",
    ]
    status_codes = {200, 201, 202, 301, 302, 307, 401, 403, 405}
    found = []

    def probe(path):
        try:
            u = urljoin(base_url + "/", path)
            resp = requests.get(u, timeout=timeout, allow_redirects=False, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; recon-master/1.0)"})
            if resp.status_code in status_codes:
                return {
                    "url": u,
                    "path": path,
                    "status": resp.status_code,
                    "size": len(resp.content),
                    "server": resp.headers.get("Server", ""),
                }
        except Exception:
            pass
        return None

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; recon-master/1.0)"})

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(probe, w): w for w in wordlist}
        for fut in as_completed(futures):
            r = fut.result()
            if r:
                found.append(r)

    if not quiet:
        print(f"\n{Colors.BOLD}[*] Module 5: Directory Brute-Forcing{Colors.END}")
        print(f"    {Colors.GREEN}[+]{Colors.END} {base_url}: {len(found)} paths found")
        for d in found[:10]:
            print(f"      {d['status']} {d['url']}")

    return sorted(found, key=lambda x: x["status"])


# =============================================================================
# MODULE 6: PARAMETER FUZZING
# =============================================================================

def fuzz_parameters(base_url, timeout=10, quiet=False):
    """Fuzz common URL parameters for reflected XSS / information disclosure."""
    test_payload = "'\"\"><script>alert(1)</script>"
    common_params = [
        "id", "q", "search", "query", "s", "keyword", "page", "cat", "category",
        "type", "action", "file", "path", "url", "redirect", "return", "next",
        "callback", "view", "name", "email", "user", "username", "search_term",
        "term", "filter", "sort", "order", "debug", "test", "admin", "config",
        "page_id", "product_id", "item", "lang", "locale", "callback_url",
    ]
    findings = []

    def probe_param(param):
        try:
            parsed = urlparse(base_url)
            qs = parse_qs(parsed.query)
            qs[param] = test_payload
            new_query = urlencode(qs, doseq=True)
            fuzzed = urlunparse((parsed.scheme, parsed.netloc, parsed.path,
                                 parsed.params, new_query, parsed.fragment))

            resp = requests.get(fuzzed, timeout=timeout, allow_redirects=False, verify=False,
                                headers={"User-Agent": "Mozilla/5.0 (compatible; recon-master/1.0)"})
            body = resp.text

            reflected = test_payload in body
            if reflected:
                findings.append({
                    "url": fuzzed,
                    "parameter": param,
                    "issue": "Reflected parameter (possible XSS)",
                    "status": resp.status_code,
                })
        except Exception:
            pass
        return None

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; recon-master/1.0)"})

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(probe_param, p): p for p in common_params}
        for fut in as_completed(futures):
            fut.result()

    if not quiet:
        print(f"\n{Colors.BOLD}[*] Module 6: Parameter Fuzzing{Colors.END}")
        if findings:
            print(f"    {Colors.GREEN}[+]{Colors.END} {base_url}: {len(findings)} findings")
            for f in findings:
                print(f"      {f['parameter']}: {f['issue']} ({f['status']})")
        else:
            print(f"    {Colors.YELLOW}[!]{Colors.END} No reflected parameters found")

    return findings


# =============================================================================
# MODULE 7: JS EXTRACTION & ANALYSIS
# =============================================================================

def extract_js_files(results, quiet=False):
    """Extract all JS files from probed results."""
    all_js = []
    for r in results:
        for u in r["js_urls"]:
            all_js.append({"host": r["host"], "url": u})

    if not quiet:
        print(f"\n{Colors.BOLD}[*] Module 7: JavaScript File Extraction{Colors.END}")
        print(f"    {Colors.GREEN}[+]{Colors.END} Total JS files found: {len(all_js)}")
        for j in all_js[:20]:
            print(f"      {j['host']} -> {j['url'][:100]}")
        if len(all_js) > 20:
            print(f"      ... and {len(all_js) - 20} more")

    return all_js


# =============================================================================
# MAIN PIPELINE
# =============================================================================

def run_pipeline():
    banner()

    # --- Inputs ---
    domain = ask("Target domain (e.g. example.com)", required=True)
    timeout = ask_int("HTTP timeout in seconds", default=10)
    max_workers = ask_int("Concurrent threads", default=15)
    save = ask("Save results to JSON file?", default="y", choices=["y", "n"])
    out_file = ask("Output filename", default=f"{domain}_recon.json") if save == "y" else None

    # Feature toggles
    do_ports = ask("Run port scan on resolved hosts?", default="n", choices=["y", "n"])
    do_dirs = ask("Run directory brute-forcing on live sites?", default="n", choices=["y", "n"])
    do_fuzz = ask("Run parameter fuzzing on live sites?", default="n", choices=["y", "n"])
    do_js = ask("Extract JavaScript files from live sites?", default="y", choices=["y", "n"])

    print(f"\n{Colors.BOLD}[*] Target: {domain}{Colors.END}")
    print(f"{Colors.BOLD}[*] Timeout: {timeout}s, Threads: {max_workers}{Colors.END}\n")

    # --- Step 1: Subdomain Enumeration ---
    subs, sources = enumerate_subdomains(domain)
    if not subs:
        print(f"\n{Colors.RED}[!] No subdomains found. Exiting.{Colors.END}")
        return

    # --- Step 2: DNS Resolution ---
    resolved, unresolved = resolve_subdomains(subs)

    # --- Step 3: HTTP Probing ---
    results = probe_all(subs, timeout=timeout, max_workers=max_workers)
    active = [r for r in results if r["active"]]

    # --- Step 4: Port Scanning ---
    port_results = {}
    if do_ports == "y":
        for ip in resolved:
            ports = scan_ports(ip, timeout=2)
            port_results[ip] = ports

    # --- Step 5: Directory Brute-Forcing ---
    dir_results = {}
    if do_dirs == "y":
        for r in active:
            base = f"{r['scheme']}://{r['host']}"
            found = brute_force_dirs(base, timeout=timeout)
            dir_results[r["host"]] = found

    # --- Step 6: Parameter Fuzzing ---
    fuzz_results = {}
    if do_fuzz == "y":
        for r in active:
            base = f"{r['scheme']}://{r['host']}"
            findings = fuzz_parameters(base, timeout=timeout)
            fuzz_results[r["host"]] = findings

    # --- Step 7: JS Extraction ---
    js_files = []
    if do_js == "y":
        js_files = extract_js_files(results)

    # --- Step 8: Summary ---
    print("\n" + "=" * 70)
    print("RECON SUMMARY")
    print("=" * 70)
    print(f"Target domain       : {domain}")
    print(f"Subdomains found    : {len(subs)}")
    print(f"Resolved IPs        : {len(resolved)}")
    print(f"Unresolved          : {len(unresolved)}")
    print(f"Total probed        : {len(results)}")
    print(f"Active/Live hosts   : {len(active)}")
    print(f"Inactive/Dead hosts : {len(results) - len(active)}")

    print("\n--- Sources ---")
    for src, cnt in sources:
        print(f"  {src}: {cnt}")

    print("\n--- Active Hosts ---")
    for r in active:
        bugs = f" | bugs: {r['bugs']}" if r["bugs"] else ""
        print(f"  {Colors.GREEN}✓{Colors.END} {r['host']} ({r['status']}) "
              f"Server: {r['server']} Title: {r['title'][:40]}{bugs}")

    if do_ports == "y":
        print("\n--- Open Ports ---")
        for ip, ports in port_results.items():
            if ports:
                print(f"  {ip}: {ports}")

    if do_dirs == "y":
        print("\n--- Directory Hits ---")
        for host, found in dir_results.items():
            if found:
                print(f"  {host}: {len(found)} paths")

    if do_fuzz == "y":
        print("\n--- Parameter Fuzzing Findings ---")
        for host, findings in fuzz_results.items():
            if findings:
                print(f"  {host}: {len(findings)} findings")

    if do_js == "y":
        print(f"\n--- JavaScript Files ---")
        print(f"  Total: {len(js_files)}")

    # --- Save Results ---
    if out_file:
        payload = {
            "target": domain,
            "subdomains": subs,
            "resolved_ips": resolved,
            "unresolved": unresolved,
            "results": results,
            "active_hosts": active,
            "js_files": js_files,
            "port_scan": port_results if do_ports == "y" else {},
            "directory_bruteforce": dir_results if do_dirs == "y" else {},
            "parameter_fuzz": fuzz_results if do_fuzz == "y" else {},
            "sources": sources,
        }
        with open(out_file, "w") as f:
            json.dump(payload, f, indent=2)
        print(f"\n{Colors.GREEN}[+]{Colors.END} Results saved to {out_file}")

    print(f"\n{Colors.BOLD}[*] Recon complete.{Colors.END}")


if __name__ == "__main__":
    try:
        run_pipeline()
    except KeyboardInterrupt:
        print(f"\n{Colors.RED}[!] Interrupted by user.{Colors.END}")
        sys.exit(1)