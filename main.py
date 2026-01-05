import requests
from bs4 import BeautifulSoup
import re
import pdfplumber
import io
import argparse
import json
import csv
import sys
import os
from datetime import datetime
from urllib.parse import urlparse

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36 Edg/134.0.0.0"

HASH_PATTERNS = {
    'md5': re.compile(r'\b[a-f0-9]{32}\b', re.IGNORECASE),
    'sha1': re.compile(r'\b[a-f0-9]{40}\b', re.IGNORECASE),
    'sha256': re.compile(r'\b[a-f0-9]{64}\b', re.IGNORECASE),
    'sha384': re.compile(r'\b[a-f0-9]{96}\b', re.IGNORECASE),
    'sha512': re.compile(r'\b[a-f0-9]{128}\b', re.IGNORECASE),
}

CHROME_EXT_PATTERN = re.compile(r'\b[a-p]{32}\b', re.IGNORECASE)
IPV4_PATTERN = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
IPV6_PATTERN = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
# Enhanced domain pattern to match multi-part domains with subdomains
# Matches patterns like: subdomain.domain.tld, sub.domain.co.uk, etc.
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}(?:\.[a-zA-Z]{2,})?\b')
URL_PATTERN = re.compile(r'https?://[^\s\'"<]+')
CRYPTO_WALLET_PATTERN = re.compile(r'\b(bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})\b')
FILE_NAME_PATTERN = re.compile(r'\b[\w\-]+\.(?:exe|dll|bat|vbs|js|cmd|ps1|py|pyw|pyc|pyd)\b', re.IGNORECASE)
FILE_PATH_PATTERN = re.compile(r'\b[A-Za-z]:[\w\.\-\\]*\w+\b')

def is_valid_ipv4(ip):
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    if any(n < 0 or n > 255 for n in nums):
        return False
    if nums[0] == 0 and ip != '0.0.0.0':
        return False
    return True

def load_tlds_from_file(filename):
    with open(filename, 'r') as f:
        lines = f.readlines()
    return set(line.strip().lower() for line in lines if line.strip())

def save_tlds_to_file(tlds, filename):
    with open(filename, 'w') as f:
        for tld in sorted(tlds):
            f.write(tld + '\n')

def fetch_tlds():
    url = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
    response = requests.get(url, headers={'User-Agent': USER_AGENT})
    response.raise_for_status()
    lines = response.text.splitlines()
    tlds = []
    for line in lines:
        if not line.startswith('#') and line.strip():
            tlds.append(line.strip().lower())
    return set(tlds)

def get_tld_list():
    filename = 'tlds.txt'
    backup = 'tlds.txt.backup'
    if os.path.exists(filename):
        mtime = os.path.getmtime(filename)
        age = datetime.now() - datetime.fromtimestamp(mtime)
        if age.days >= 15:
            # backup
            if os.path.exists(backup):
                os.remove(backup)
            os.rename(filename, backup)
            # download new
            tlds = fetch_tlds()
            save_tlds_to_file(tlds, filename)
        else:
            tlds = load_tlds_from_file(filename)
    else:
        tlds = fetch_tlds()
        save_tlds_to_file(tlds, filename)
    return tlds

def extract_iocs(text, tlds, html=None):
    # Refang common defanging techniques
    text = text.replace('[.]', '.').replace('(.)', '.')
    if html:
        html = html.replace('[.]', '.').replace('(.)', '.')

    iocs = {
        'hashes': [],
        'chrome_extensions': [],
        'domains': [],
        'ips': [],
        'emails': [],
        'crypto_wallets': [],
        'file_names': [],
        'file_paths': [],
        'urls': []
    }

    # Hashes
    for hash_type, pattern in HASH_PATTERNS.items():
        matches = pattern.findall(text)
        iocs['hashes'].extend([(hash_type.upper(), match.lower()) for match in matches])

    # Chrome extensions - 32 char letters a-p not overlapping with hashes
    chrome_matches = CHROME_EXT_PATTERN.findall(text)
    hash_values = {value for _, value in iocs['hashes']}
    for match in chrome_matches:
        match_lower = match.lower()
        if len(match) == 32 and match_lower not in hash_values:
            iocs['chrome_extensions'].append(match_lower)

    # IPs
    ipv4_matches = [ip for ip in IPV4_PATTERN.findall(text) if is_valid_ipv4(ip)]
    iocs['ips'].extend([('IPv4', ip) for ip in ipv4_matches])
    ipv6_matches = IPV6_PATTERN.findall(text)
    iocs['ips'].extend([('IPv6', ip.lower()) for ip in ipv6_matches])

    # Emails
    email_matches = EMAIL_PATTERN.findall(text)
    iocs['emails'].extend(email_matches)

    # Domains - candidate collection and scoring to prefer relevant hosts
    # Collect domain-like candidates from text and raw HTML
    domain_matches_text = DOMAIN_PATTERN.findall(text)
    domain_matches_html = DOMAIN_PATTERN.findall(html) if html else []
    candidate_domains = set(domain_matches_text + domain_matches_html)

    # Extract URLs from text and collect their netlocs with path info
    url_matches = URL_PATTERN.findall(text)
    iocs['urls'].extend(url_matches)
    url_netlocs = {}
    for url in url_matches:
        try:
            parsed = urlparse(url)
            netloc = parsed.netloc.lower()
            if ':' in netloc:
                netloc = netloc.split(':')[0]
            if netloc:
                url_netlocs.setdefault(netloc, []).append(parsed.path or '')
                candidate_domains.add(netloc)
        except Exception:
            continue

    # If we have HTML, extract domains from href/src attributes (strong signal)
    html_attr_domains = set()
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup.find_all(True):
                for attr in ('href', 'src', 'data-src', 'srcset'):
                    val = tag.get(attr)
                    if not val:
                        continue
                    # urls inside srcset are comma separated
                    candidates = []
                    if attr == 'srcset':
                        parts = [p.strip().split(' ')[0] for p in val.split(',') if p.strip()]
                        candidates.extend(parts)
                    else:
                        candidates.append(val)
                    for cand in candidates:
                        # try to extract netloc if cand contains a URL
                        m = URL_PATTERN.search(cand)
                        if m:
                            try:
                                parsed = urlparse(m.group(0))
                                netloc = parsed.netloc.lower()
                                if ':' in netloc:
                                    netloc = netloc.split(':')[0]
                                if netloc:
                                    html_attr_domains.add(netloc)
                                    candidate_domains.add(netloc)
                            except Exception:
                                continue
                        else:
                            # maybe it's a bare domain
                            if DOMAIN_PATTERN.search(cand):
                                html_attr_domains.add(cand.lower())
                                candidate_domains.add(cand.lower())
        except Exception:
            pass

    # Scoring signals and thresholds
    SUSPICIOUS_KEYWORDS = ['blob', 'download', 'payload', 'malware', 'ransom', 'exe', 'dll', 'attack', 'c2', 'command', 'control', 'drop', 'upload', 'payload']
    KNOWN_BENIGN_TOKENS = ['windows', 'microsoft', 'google', 'amazonaws', 'cloudfront', 'cloudflare', 'akamai', 'cdn', 'googleapis', 'yahoo', 'bing', 'youtube']

    domain_scores = {}

    def passes_tld_check(domain):
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        tld = parts[-1]
        if tld not in tlds:
            return False
        if len(parts) == 3:
            two_level_tld = f"{parts[-2]}.{parts[-1]}"
            if two_level_tld in tlds:
                return True
            # If middle part is a TLD but leftmost is not, likely a namespace -> reject
            if parts[-2] in tlds and parts[0] not in tlds:
                return False
        # For 4+ parts accept if rightmost tld valid (covers blob.core.windows.net)
        return True

    for domain in candidate_domains:
        domain_lower = domain.lower()
        if not passes_tld_check(domain_lower):
            continue

        score = 0.0
        # strong signals
        if domain_lower in html_attr_domains:
            score += 2.0
        if domain_lower in url_netlocs:
            score += 2.0

        # frequency in text
        freq = text.lower().count(domain_lower)
        score += min(3.0, 0.5 * freq)

        # surrounding keywords window check (first occurrence)
        idx = text.lower().find(domain_lower)
        if idx != -1:
            window = text[max(0, idx - 80): idx + len(domain_lower) + 80].lower()
            kw_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in window)
            score += min(2.0, 0.5 * kw_count)

        # path analysis from collected URLs for this domain
        paths = url_netlocs.get(domain_lower, [])
        for p in paths:
            if '/blob' in p or 'blob.core' in domain_lower:
                score += 1.0
            # file extension in path
            if re.search(r'\.(exe|zip|rar|dll|scr|js|ps1|bat|msi)\b', p, re.IGNORECASE):
                score += 1.0

        # small negative weight for known benign tokens to reduce false positives
        if any(token in domain_lower for token in KNOWN_BENIGN_TOKENS):
            score -= 0.5

        domain_scores[domain_lower] = round(score, 2)

    # Select domains above threshold and populate iocs['domains']
    SCORE_THRESHOLD = 2.1
    scored_list = sorted(domain_scores.items(), key=lambda x: x[1], reverse=True)
    iocs['domain_scores'] = scored_list
    final_domains = [d for d, s in scored_list if s >= SCORE_THRESHOLD]
    iocs['domains'].extend(final_domains)

    # Crypto wallets
    crypto_matches = CRYPTO_WALLET_PATTERN.findall(text)
    iocs['crypto_wallets'].extend(crypto_matches)

    # File names
    file_name_matches = FILE_NAME_PATTERN.findall(text)
    iocs['file_names'].extend(file_name_matches)

    # File paths
    file_path_matches = [match.group(0) for match in FILE_PATH_PATTERN.finditer(text)]
    iocs['file_paths'].extend(file_path_matches)

    # Remove duplicates
    for key in iocs:
        if key in ('hashes', 'ips'):
            iocs[key] = list(dict.fromkeys(iocs[key]))
        else:
            iocs[key] = list(dict.fromkeys(iocs[key]))

    return iocs

def fetch_url_content(url):
    response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10)
    response.raise_for_status()
    content_type = response.headers.get('content-type', '').lower()
    if 'application/pdf' in content_type:
        pdf_file = io.BytesIO(response.content)
        with pdfplumber.open(pdf_file) as pdf:
            text = ''
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + '\n'
        return text, True
    else:
        return response.text, False


def parse_html_to_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    return soup.get_text()

def output_stdout(iocs):
    for category, items in iocs.items():
        if category == 'domain_scores':
            continue  # Skip raw scores in stdout, show in domains with score
        print(f"{category.upper()}:")
        if category == 'hashes':
            for hash_type, value in items:
                print(f"  {hash_type}: {value}")
        elif category == 'ips':
            for ip_type, value in items:
                print(f"  {ip_type}: {value}")
        elif category == 'domains':
            # Show domains with their scores
            score_dict = dict(iocs.get('domain_scores', []))
            for item in items:
                score = score_dict.get(item, 0.0)
                print(f"  {item} (score: {score})")
        else:
            for item in items:
                print(f"  {item}")
        print()

def output_csv(iocs, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'Type', 'Value', 'Score'])
        score_dict = dict(iocs.get('domain_scores', []))
        for category, items in iocs.items():
            if category == 'domain_scores':
                continue  # Skip raw scores
            if category == 'hashes':
                for hash_type, value in items:
                    writer.writerow([category, hash_type, value, ''])
            elif category == 'ips':
                for ip_type, value in items:
                    writer.writerow([category, ip_type, value, ''])
            elif category == 'domains':
                for item in items:
                    score = score_dict.get(item, 0.0)
                    writer.writerow([category, '', item, score])
            else:
                for item in items:
                    writer.writerow([category, '', item, ''])

def output_json(iocs, filename):
    with open(filename, 'w') as jsonfile:
        json.dump(iocs, jsonfile, indent=4)

def output_raw(iocs):
    all_iocs = []
    for category, items in iocs.items():
        if category == 'domain_scores':
            continue  # Skip scores in raw output
        if category == 'hashes':
            all_iocs.extend([value for _, value in items])
        elif category == 'ips':
            all_iocs.extend([value for _, value in items])
        else:
            all_iocs.extend(items)
    for ioc in all_iocs:
        print(ioc)

def main():
    parser = argparse.ArgumentParser(description='Extract IOCs from a webpage.')
    parser.add_argument('url', help='URL of the webpage to analyze')
    parser.add_argument('--format', choices=['stdout', 'csv', 'json', 'raw'], default='stdout', help='Output format')
    parser.add_argument('--output', help='Output file for csv or json')
    args = parser.parse_args()

    print("Warning: This is a best effort extraction. Please check the original source for accuracy.")

    try:
        print("Loading TLD list...")
        tlds = get_tld_list()
        print("Fetching content...")
        content, is_pdf = fetch_url_content(args.url)
        if is_pdf:
            text = content
            html = None
            print("Extracted text from PDF...")
        else:
            text = parse_html_to_text(content)
            html = content
            print("Parsed HTML to text...")
        print("Extracting IOCs...")
        iocs = extract_iocs(text, tlds, html)

        if args.format == 'stdout':
            output_stdout(iocs)
        elif args.format == 'csv':
            if not args.output:
                print("Error: --output required for csv")
                sys.exit(1)
            output_csv(iocs, args.output)
        elif args.format == 'json':
            if not args.output:
                print("Error: --output required for json")
                sys.exit(1)
            output_json(iocs, args.output)
        elif args.format == 'raw':
            output_raw(iocs)

        total_iocs = sum(len(items) for items in iocs.values())
        print(f"Total IOCs found: {total_iocs}")

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
