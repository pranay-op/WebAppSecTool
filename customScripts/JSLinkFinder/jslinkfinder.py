import requests
from bs4 import BeautifulSoup
import re
import json
import base64
from collections import defaultdict
import math
import logging
import random
from concurrent.futures import ThreadPoolExecutor
from fake_useragent import UserAgent
import argparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# List of user agents to rotate
ua = UserAgent()

# List of proxies to rotate
proxies = [
    "http://10.10.1.10:3128",
    "http://10.10.1.11:3128",
    "http://51.158.68.68:8811",
    "http://91.207.238.107:8080",
    "http://206.189.231.226:3128",
    "http://134.209.29.120:3128",
    "http://167.99.249.151:8080",
    "http://167.71.5.83:8080",
    "http://206.189.157.252:3128",
    "http://68.183.181.11:3128",
    "http://188.166.162.1:3128",
    "http://134.209.29.120:8080",
    "http://188.166.83.34:8080",
    "http://159.65.69.186:3128",
    "http://206.189.158.22:3128",
    "http://64.225.68.102:3128",
    "http://165.22.52.19:8080",
    "http://165.227.215.71:8080",
    "http://142.93.60.240:3128",
    "http://138.68.60.8:8080",
    "http://188.166.83.20:3128",
    "http://159.89.49.9:3128",
    "http://188.166.162.1:8080",
    "http://178.62.193.19:3128",
    "http://165.22.80.86:8080"
]

# Entropy calculation function
def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    length = len(data)
    for x in range(256):
        p_x = data.count(chr(x)) / length
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy

# Function to find secrets
def find_secrets(js_content):
    secrets = re.findall(r'(api_key|secret|password|token|key|auth)=["\']?([a-zA-Z0-9_\-]+)["\']?', js_content, re.IGNORECASE)
    return secrets

# Function to find subdomains
def find_subdomains(js_content, domain):
    subdomains = re.findall(r'(https?://[a-zA-Z0-9\-]+\.{0}\.[a-zA-Z0-9\-\.]+)'.format(domain), js_content)
    return subdomains

# Function to find cloud URLs
def find_cloud_urls(js_content):
    patterns = {
        'AWS': r'(https?://[a-zA-Z0-9\-\.]*\.amazonaws\.com)',
        'Google': r'(https?://[a-zA-Z0-9\-\.]*\.googleapis\.com)',
        'Azure': r'(https?://[a-zA-Z0-9\-\.]*\.windows\.net)',
        'CloudFront': r'(https?://[a-zA-Z0-9\-\.]*\.cloudfront\.net)',
        'Digital Ocean': r'(https?://[a-zA-Z0-9\-\.]*\.digitaloceanspaces\.com)',
        'Oracle': r'(https?://[a-zA-Z0-9\-\.]*\.oraclecloud\.com)',
        'Alibaba': r'(https?://[a-zA-Z0-9\-\.]*\.aliyuncs\.com)',
        'Firebase': r'(https?://[a-zA-Z0-9\-\.]*\.firebaseio\.com)',
        'Rackspace': r'(https?://[a-zA-Z0-9\-\.]*\.rackcdn\.com)',
        'DreamHost': r'(https?://[a-zA-Z0-9\-\.]*\.dreamhost\.com)',
    }
    cloud_urls = defaultdict(list)
    for cloud, pattern in patterns.items():
        matches = re.findall(pattern, js_content)
        if matches:
            cloud_urls[cloud].extend(matches)
    return cloud_urls

# Function to find API endpoints
def find_api_endpoints(js_content):
    endpoints = re.findall(r'(https?://[a-zA-Z0-9\-/\.]*\/api\/[a-zA-Z0-9\-/\.]*)', js_content)
    return endpoints

# Function to scan a JavaScript file
def scan_js_file(url, domain):
    try:
        headers = {'User-Agent': ua.random}
        proxy = {'http': random.choice(proxies), 'https': random.choice(proxies)}
        response = requests.get(url, headers=headers, proxies=proxy)
        response.raise_for_status()
        js_content = response.text

        secrets = find_secrets(js_content)
        subdomains = find_subdomains(js_content, domain)
        cloud_urls = find_cloud_urls(js_content)
        api_endpoints = find_api_endpoints(js_content)

        return {
            'secrets': secrets,
            'subdomains': subdomains,
            'cloud_urls': cloud_urls,
            'api_endpoints': api_endpoints,
            'entropy': calculate_entropy(js_content)
        }
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return {}

# Function to scan a website for JavaScript files
def scan_website(url):
    try:
        headers = {'User-Agent': ua.random}
        proxy = {'http': random.choice(proxies), 'https': random.choice(proxies)}
        response = requests.get(url, headers=headers, proxies=proxy)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script', src=True)
        results = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(scan_js_file, script['src'] if script['src'].startswith('http') else url + script['src'], url.split('//')[-1].split('/')[0]) for script in scripts]
            for future in futures:
                result = future.result()
                if result:
                    results.append(result)
        return results
    except requests.RequestException as e:
        logging.error(f"Error fetching {url}: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description='JS Miner - Scan websites for JS files and extract useful information.')
    parser.add_argument('url', help='Target URL to scan')
    args = parser.parse_args()

    scan_results = scan_website(args.url)
    print(json.dumps(scan_results, indent=4))

if __name__ == "__main__":
    main()

