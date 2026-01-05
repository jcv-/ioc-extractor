import requests
from bs4 import BeautifulSoup
import re
import argparse
import json
import csv
import sys
import os
from datetime import datetime

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
DOMAIN_PATTERN = re.compile(r'\b[a-zA-Z0-9-]+\.[a-zA-Z]{2,}\b')
CRYPTO_WALLET_PATTERN = re.compile(r'\b(bc(0([ac-hj-np-z02-9]{39}|[ac-hj-np-z02-9]{59})|1[ac-hj-np-z02-9]{8,87})|[13][a-km-zA-HJ-NP-Z1-9]{25,35})\b')
FILE_NAME_PATTERN = re.compile(r'\b[\w\-]+\.(?:exe|dll|bat|vbs|js|cmd|ps1|py|pyw|pyc|pyd)\b', re.IGNORECASE)
FILE_PATH_PATTERN = re.compile(r'\b(?:[A-Za-z]:[\w\.\-\\]*\w+|/\w+/\w+)\b')

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

def extract_iocs(text, tlds):
    # Refang common defanging techniques
    text = text.replace('[.]', '.').replace('(.)', '.')

    iocs = {
        'hashes': [],
        'chrome_extensions': [],
        'domains': [],
        'ips': [],
        'emails': [],
        'crypto_wallets': [],
        'file_names': [],
        'file_paths': []
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
    ipv4_matches = IPV4_PATTERN.findall(text)
    iocs['ips'].extend([('IPv4', ip) for ip in ipv4_matches])
    ipv6_matches = IPV6_PATTERN.findall(text)
    iocs['ips'].extend([('IPv6', ip.lower()) for ip in ipv6_matches])

    # Emails
    email_matches = EMAIL_PATTERN.findall(text)
    iocs['emails'].extend(email_matches)

    # Domains
    domain_matches = DOMAIN_PATTERN.findall(text)
    for domain in domain_matches:
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = parts[-1].lower()
            if tld in tlds:
                iocs['domains'].append(domain.lower())

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
        if key == 'hashes':
            iocs[key] = list(dict.fromkeys(iocs[key]))
        elif key == 'ips':
            iocs[key] = list(dict.fromkeys(iocs[key]))
        else:
            iocs[key] = list(dict.fromkeys(iocs[key]))

    return iocs

def fetch_url_content(url):
    response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=10)
    response.raise_for_status()
    return response.text

def parse_html_to_text(html):
    soup = BeautifulSoup(html, 'html.parser')
    return soup.get_text()

def output_stdout(iocs):
    for category, items in iocs.items():
        print(f"{category.upper()}:")
        if category == 'hashes':
            for hash_type, value in items:
                print(f"  {hash_type}: {value}")
        elif category == 'ips':
            for ip_type, value in items:
                print(f"  {ip_type}: {value}")
        else:
            for item in items:
                print(f"  {item}")
        print()

def output_csv(iocs, filename):
    with open(filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Category', 'Type', 'Value'])
        for category, items in iocs.items():
            if category == 'hashes':
                for hash_type, value in items:
                    writer.writerow([category, hash_type, value])
            elif category == 'ips':
                for ip_type, value in items:
                    writer.writerow([category, ip_type, value])
            else:
                for item in items:
                    writer.writerow([category, '', item])

def output_json(iocs, filename):
    with open(filename, 'w') as jsonfile:
        json.dump(iocs, jsonfile, indent=4)

def output_raw(iocs):
    all_iocs = []
    for category, items in iocs.items():
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

    try:
        print("Loading TLD list...")
        tlds = get_tld_list()
        print("Fetching webpage content...")
        html = fetch_url_content(args.url)
        text = parse_html_to_text(html)
        print("Extracting IOCs...")
        iocs = extract_iocs(text, tlds)

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

    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
