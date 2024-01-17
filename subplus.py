# """
#  ______   _______  _______  _        _______  _______  _______ 
# (  __  \ (  ____ \(  ____ \| \    /\(  ____ )(  ___  )(  ___  )
# | (  \  )| (    \/| (    \/|  \  / /| (    )|| (   ) || () () |
# | |   ) || (__    | (_____ |  (_/ / | (____)|| (___) || || || |
# | |   | ||  __)   (_____  )|   _ (  |     __)|  ___  || |(_)| |
# | |   ) || (            ) ||  ( \ \ | (\ (   | (   ) || |   | |===>("Ali")
# | (__/  )| (____/\/\____) ||  /  \ \| ) \ \__| )   ( || )   ( |
# (______/ (_______/\_______)|_/    \/|/   \__/|/     \||/     \|
# """         ___                  

import sublist3r
import requests
import socket
import argparse
import ssl
import sys
import cfscrape
from concurrent.futures import ThreadPoolExecutor
import re
from termcolor import colored
import pyfiglet
import asyncio

loop = asyncio.get_event_loop()
logo = pyfiglet.figlet_format('SubsPlus')
print(colored(logo,color="blue"))

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--domain", dest="domain", help="This place is for domain domain")
    parser.add_argument("-su", "--subs" , dest="subs", help="This place is for subdomain urls subs.txt", default="subs.txt")
    parser.add_argument('-es', dest='act_true', help='value true or false', default="false")
    parser.add_argument("-s", dest="service", help="This place is for service service.txt", required='-es' in sys.argv, default="service.txt")
    parser.add_argument("-r", dest="read", help="This place is for read read.txt", required='-es' in sys.argv, default="subs.txt")
    options = parser.parse_args()
    if not options.domain:
        parser.error("[-] Specify a -d domain option , please type -h for help")
    return options

options = get_arguments()

if not options.subs.endswith('.txt') or not options.subs:
    print("Please provide a valid subdomains namefile.txt.")
elif not options.service.endswith('.txt') or not options.service:
    print("Please provide a valid service namefile.txt.")
elif not options.read.endswith('.txt') or not options.read:
    print("Please provide a valid read namefile.txt.")

def extract_subdomains(domain):
    subdomains = sublist3r.main(domain, 40, savefile=None, ports=None, silent=True, verbose=False,
                                enable_bruteforce=False, engines=None)
    return subdomains

def find_hidden_subdomains(domain):
    url = "https://crt.sh/?q=%.{0}&output=json".format(domain)
    try:
        response = requests.get(url)
        data = response.json()
        subdomains = set()
        for item in data:
            subdomains.add(item['name_value'])
        return subdomains
    except requests.exceptions.RequestException as e:
        return []

def gather_dns_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as e:
        return None

def gather_ssl_info(domain, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, port)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return cert
    except (socket.error, ssl.SSLError) as e:
        return None

def remove_duplicates(lst):
    return list(set(lst))

def save_subdomains_to_file(subdomains, hidden_subdomains):
    all_subdomains = subdomains + hidden_subdomains
    unique_subdomains = []
    with open(options.subs, 'w') as file:
        for subdomain in all_subdomains:
            if subdomain not in unique_subdomains:
                file.write(subdomain + '\n')
                unique_subdomains.append(subdomain)
    print("All Subdomains:")
    for subdomain in unique_subdomains:
        print(subdomain)

def main():
    print('Telegram: @DeskRam.\n')
    subdomains = extract_subdomains(options.domain)
    hidden_subdomains = find_hidden_subdomains(options.domain)
    ip_ranges = []
    print(f"\nTarget Domain: {options.domain}")
    print("Subdomains:")
    for subdomain in subdomains:
        print(subdomain)
        ip = gather_dns_info(subdomain)
        if ip:
            ip_ranges.append(ip)

    print("Hidden Subdomains:")
    for hidden_subdomain in hidden_subdomains:
        print(hidden_subdomain)
        ip = gather_dns_info(hidden_subdomain)
        if ip:
            ip_ranges.append(ip)

    hidden_subdomains = remove_duplicates(hidden_subdomains)
    subdomains = remove_duplicates(subdomains)
    save_subdomains_to_file(subdomains, hidden_subdomains)
    print("IP Ranges:")
    for ip in remove_duplicates(ip_ranges):
        print(ip)

    if options.act_true.lower() == 'true':
        use_checkfree_tool()
    else:
        pass

def print_status(address, status_code, server):
    if server:
        server = server.lower()
        if any(name in server for name in ['cloudflare', 'cloudfront', 'akamai', 'AkamaiGHost']):
            print(f"[+] {address} - {status_code} OK ({server})")
        elif any(name in server for name in ['varnish', 'litespeed', 'fastly', 'nginx']):
            print(f"[+] {address} - {status_code} OK ({server})")
        else:
            print(f"[+] {address} - {status_code} OK ({server})")
    else:
        print(f"[+] {address} - {status_code} OK (Server type unknown)")

    with open(options.service, 'a') as file:
        file.write(address + '\n')

def check_address(address, headers=None):
    try:
        scraper = cfscrape.create_scraper()
        headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/526.16 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
        }
        response = scraper.get(address, headers=headers, timeout=60, allow_redirects=True, verify=False)
        status_code = response.status_code
        server = response.headers.get('Server')
        if status_code == 200:
            print_status(address, status_code, server)
        else:
            print(f"[-] {address} - {status_code} {response.reason}")
    except requests.exceptions.RequestException as e:
        if isinstance(e, requests.exceptions.SSLError):
            print(f"[-] {address} - SSL Error: {str(e)}")
        else:
            print(f"[-] {address} - Connection Error: {str(e)}")
    except Exception as ex:
        print(f"[-] {address} - An unexpected error occurred: {str(ex)}")

def use_checkfree_tool():
    with open(options.read, 'r') as file:
        hosts = file.readlines()

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [executor.submit(check_address, re.sub(r'^(https?://)?', r'https://', host.strip())) for host in hosts]

        for future in futures:
            future.result()

if __name__ == "__main__":
    main()
