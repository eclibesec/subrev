import os
import sys
import requests
import subprocess
import shutil
import zipfile
import socket
import threading
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from concurrent.futures import ThreadPoolExecutor
from time import sleep
import time
from colorama import init, Fore, Style
import getpass
import webbrowser
import json


init()
processed_ips = set()
written_domains = set()
REQUIRED_MODULES = ['requests', 'colorama']
file_lock = threading.Lock()
REPO_OWNER = 'eclibesec'
REPO_NAME = 'subrev'
LOCAL_VERSION_FILE = 'version.txt'
if os.name == 'nt':
    UPDATE_FOLDER = os.path.join(os.getenv('TEMP'), 'subrev_update')
else:
    UPDATE_FOLDER = os.path.join('/tmp', 'subrev_update')
is_exe = getattr(sys, 'frozen', False)
CURRENT_FILE = 'subrev.exe' if is_exe else 'subrev.py'
GITHUB_EXE_URL = f'https://github.com/{REPO_OWNER}/{REPO_NAME}/blob/main/subrev.exe?raw=true'
GITHUB_PY_URL = f'https://github.com/{REPO_OWNER}/{REPO_NAME}/blob/main/subrev.py?raw=true'
def install_missing_modules():
    for module in REQUIRED_MODULES:
        try:
            __import__(module)
        except ImportError:
            print(f"Module '{module}' not found. Installing...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])
install_missing_modules()
def clean_domain(domain):
    FILTERED_PREFIXES = ['www.', 
                         'webmail.', 
                         'cpanel.', 
                         'cpcalendars.', 
                         'cpcontacts.', 
                         'webdisk.', 
                         'mail.',
                         'whm.', 
                         'autodiscover.',
                         'slot.',
                         'slot-gacor.',
                         'server-thailand.',
                         'slot-zeus,',
                         'situs-slot-gacor.',
                         'situs-slot.',
                         'situsmpo.',
                         'situsslot.',
                         'situsslot777.',
                         'siot8tussl8.'
                         'situsslot88wajib.',
                         'situsslotresmi.',
                         'situsslotthailand.',
                         'situstoto.',
                         'situsslotgacorlinkslotterpercaya.',
                         'situs-toto.',
                         'situs-slot88.', 
                         'situs-casino-online.',
                         'situs4d.',
                         'slot-5000.',
                         'slot-10k.',
                         'slot-88.',
                         'slot-asia.',
                         'slot-bonus.',
                         'slot-bri.']
    cleaned_domain = domain
    for prefix in FILTERED_PREFIXES:
        if domain.startswith(prefix):
            domain = domain[len(prefix):]  
            break
    return domain
def domain_to_ip(domain_name):
    if not is_valid_domain(domain_name):
        return None
    try:
        domain_name.encode('idna')
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except (socket.gaierror, UnicodeError):
        return None
def is_valid_domain(domain):
    if len(domain) > 253 or len(domain) == 0:
        return False
    labels = domain.split('.')
    return all(0 < len(label) <= 63 for label in labels)
def remove_duplicates(output_file):
    try:
        with open(output_file, "r", encoding="utf-8") as file:
            lines = file.readlines()
        unique_lines = list(set(line.strip() for line in lines))
        with open(output_file, "w", encoding="utf-8") as file:
            for line in sorted(unique_lines):
                file.write(line + "\n")
        print(f"{Fore.GREEN}Duplicates removed from '{output_file}'.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error while removing duplicates: {e}{Style.RESET_ALL}")
def save_api_key(apikey):
    config_folder = 'subrev'
    config_file_path = os.path.join(config_folder, 'config.json')
    if not os.path.exists(config_folder):
        os.makedirs(config_folder)
    config_data = {"apikey": apikey}
    with open(config_file_path, 'w', encoding='utf-8') as config_file:
        json.dump(config_data, config_file)
def load_api_key():
    config_folder = 'subrev'
    config_file_path = os.path.join(config_folder, 'config.json')
    if os.path.exists(config_file_path):
        with open(config_file_path, 'r', encoding='utf-8') as config_file:
            config_data = json.load(config_file)
            return config_data.get('apikey', None)
    return None
def validate_api_key(apikey):
    url = f"https://eclipsesec.tech/api/?apikey={apikey}&validate=true"
    debug_file_path = "debug.txt"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        body = response.json()
        try:
            with open(debug_file_path, "a", encoding="utf-8") as debug_file:
                debug_file.write(f"API Response: {body}\n")
        except OSError as e:
            print(f"{Fore.RED}Failed to write to debug file: {str(e)}{Style.RESET_ALL}")
        if body.get("error") == "User not found!":
            print(f"{Fore.RED}Error: {body.get('error')}{Style.RESET_ALL}")
            return "", False
        if body.get("error") == "Request limit reached. Please wait until it resets.":
            print(f"{Fore.RED}API limit reached: {body.get('error')}{Style.RESET_ALL}")
            return "", False
        if body.get('status') == "valid":
            save_api_key(apikey)
            return body.get('user'), True
        else:
            print(f"{Fore.RED}Invalid API key: {body.get('message', 'Unknown error')}{Style.RESET_ALL}")
            return "", False
    except requests.exceptions.HTTPError as http_err:
        print(f"{Fore.RED}HTTP error during API key validation: {http_err}{Style.RESET_ALL}")
        return "", False

    except requests.exceptions.RequestException as req_err:
        print(f"{Fore.RED}Error during API key validation: {req_err}{Style.RESET_ALL}")
        return "", False
    except Exception as e:
        try:
            with open(debug_file_path, "a", encoding="utf-8") as debug_file:
                debug_file.write(f"Unhandled error during API key validation: {str(e)}\n")
        except OSError as file_err:
            print(f"{Fore.RED}Failed to write error log: {str(file_err)}{Style.RESET_ALL}")
        print(f"{Fore.RED}API key validation failed: {e}{Style.RESET_ALL}")
        return "", False
def reverse_ip(ip, apikey, output_file, domain_filter=None):
    global processed_ips, written_domains
    if ip in processed_ips:
        print(f"{Fore.YELLOW}[ {ip} - sameIP ]{Style.RESET_ALL}")
        return
    processed_ips.add(ip)
    url = f"https://eclipsesec.tech/api/?reverseip={ip}&apikey={apikey}"
    try:
        response = requests.get(url)  
        response.raise_for_status()
        body = response.json()
        if body.get("error") == "Request limit reached. Please wait until it resets.":
            return
        if not body.get("domains") or body["domains"] == "No data available":
            return
        domains = body["domains"]
        print(f"[{Fore.GREEN}Reversing {ip} -> {len(domains)} domains found{Style.RESET_ALL}]")
        with file_lock:
            with open(output_file, "a", encoding="utf-8") as f:
                for domain in domains:
                    if domain_filter and domain.endswith(domain_filter):
                        if domain not in written_domains:
                            f.write(domain + "\n")
                            written_domains.add(domain)
                    elif not domain_filter:
                        if domain not in written_domains:
                            f.write(domain + "\n")
                            written_domains.add(domain)
    except:
        pass
def subdomain_finder(domain, apikey, output_file):
    url = f"https://eclipsesec.tech/api/?subdomain={domain}&apikey={apikey}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        body = response.json()
        if body.get("error") == "Request limit reached. Please wait until it resets.":
            print(f"{Fore.RED}API limit reached: {body.get('error')}{Style.RESET_ALL}")
            return
        domains = body["domains"]
        if domains:
            print(f"[{Fore.GREEN}Extracting {domain} -> {len(domains)} subdomains{Style.RESET_ALL}]")
            unique_domains = set()
            for subdomain in domains:
                cleaned = clean_domain(subdomain)
                if cleaned:
                    unique_domains.add(cleaned)
            with file_lock, open(output_file, "a") as f:
                for unique_domain in sorted(unique_domains):
                    f.write(unique_domain + "\n")
        else:
            print(f"{Fore.YELLOW}[ No data for domain - {domain} ]{Style.RESET_ALL}")
    except:
        pass
def discovery_domain_engine(apikey):
    print(Fore.GREEN + "[ Discovery Domain Engine started ] ..." + Style.RESET_ALL)
    extension_filter = input("Enter domain extension filter (e.g., 'id', 'com', leave empty for all): ").strip()
    num_scrapes = int(input("Enter how many times to scrape: ").strip())
    delay = float(input("Enter delay between requests (in seconds): ").strip())
    output_file = input("Save results to (output file): ").strip()
    url = f"https://eclipsesec.tech/api/?discovery=true&apikey={apikey}"
    if extension_filter:
        url += f"&extension={extension_filter}"
    for i in range(num_scrapes):
        print(f"{Fore.CYAN}[Scraping attempt {i + 1}... ]{Style.RESET_ALL}")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            body = response.json()
            if "domains" in body and isinstance(body["domains"], list):
                domains = body["domains"]
                print(f"{Fore.GREEN}Found {len(domains)} domains.{Style.RESET_ALL}")
                with file_lock, open(output_file, "a", encoding="utf-8") as f:
                    for domain in domains:
                        f.write(domain + "\n")
            else:
                print(f"{Fore.YELLOW}[No domains found in this scrape]{Style.RESET_ALL}")
            sleep(delay)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}Request error: {str(e)}{Style.RESET_ALL}")
    print(f"{Fore.GREEN}Discovery completed. Results saved to {output_file}.{Style.RESET_ALL}")
def grab_by_date(page, apikey, date, output_file, bad_domains_file='bad_domains.txt'):
    url = f"https://eclipsesec.tech/api/?bydate={date}&page={page}&apikey={apikey}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        body = response.json()

        if not body.get('domains') or isinstance(body['domains'], str):
            if body.get("error") == "Request limit reached. Please wait until it resets.":
                print(f"{Fore.RED}API limit reached, please extend the limit to Telegram @no4meee{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No Data on page[{page}]. please wait until grabbing done...{Style.RESET_ALL}")
            return False

        print(f"page [{page}] -> domains found [{len(body['domains'])}]")
        with file_lock, open(output_file, "a") as f:
            for domain in body['domains']:
                if isinstance(domain, str) and domain.strip():
                    f.write(domain + "\n")
        return True
    except requests.exceptions.HTTPError as http_err:
        if response.status_code in [502, 520, 500]:
            print(f"{Fore.YELLOW}Retrying... page {page}. (Waiting for the server to respond){Style.RESET_ALL}")
            sleep(2)
        else:
            print(f"{Fore.RED}page {page} NO DOMAINS{Style.RESET_ALL}")
        return False
    except Exception as e:
        print(f"{Fore.RED}Error during Grab by Date: {e}{Style.RESET_ALL}")
        return False
def domain_to_ip_tool():
    try:
        print(Fore.GREEN + "Domain to IP tool started..." + Style.RESET_ALL)
        file_name = input("$ give me your file: ").strip()
        output_file_name = input("$ output filename? : ").strip()
        while True:
            thread_count_str = input("threads > 1-100: ").strip()
            if thread_count_str.isdigit():
                thread_count = int(thread_count_str)
                if 1 <= thread_count <= 100:
                    break
                else:
                    print(f"{Fore.RED}Thread count must be between 1 and 100.{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}Thread count must be a number.{Style.RESET_ALL}")
        with open(file_name, 'r', encoding='utf-8') as file:
            domains = file.readlines()
        domains = [domain.strip() for domain in domains]

        def process_domain(domain):
            ip_address = domain_to_ip(domain)
            if ip_address:
                print(f"[{Fore.GREEN}{domain} -> {ip_address}{Style.RESET_ALL}]")
                with file_lock, open(output_file_name, "a") as f:
                    f.write(f"{ip_address}\n")
                return ip_address
            else:
                print(f"[{Fore.RED}bad -> {domain}{Style.RESET_ALL}]")
                return None
        with ThreadPoolExecutor(max_workers=thread_count) as executor:
            executor.map(process_domain, domains)
        print(f"Data has been saved to '{output_file_name}'")
    except FileNotFoundError:
        print(f"{Fore.RED}File '{file_name}' not found.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
def check_for_updates():
    print("Checking for updates...")
    latest_version = get_latest_version()
    if not latest_version:
        return
    local_version = get_local_version()
    if local_version is None or latest_version != local_version:
        print(f"New version available: {latest_version}. Downloading update...")
        download_url = GITHUB_EXE_URL if is_exe else GITHUB_PY_URL
        output_path = os.path.join(UPDATE_FOLDER, CURRENT_FILE)
        update_file_path = download_update(download_url, output_path)
        if update_file_path:
            apply_update(update_file_path, os.path.abspath(sys.argv[0]))
        else:
            print("Failed to download the update.")
    else:
        print(f"You are already using the latest version: {local_version}.")
def get_latest_version():
    url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/commits/main"
    try:
        response = requests.get(url)
        response.raise_for_status()
        latest_commit = response.json()
        latest_version = latest_commit['sha'][:7]
        return latest_version
    except Exception as e:
        print(f"{Fore.RED}Error checking for updates: {e}{Style.RESET_ALL}")
        return None
def get_local_version():
    if os.path.exists(LOCAL_VERSION_FILE):
        with open(LOCAL_VERSION_FILE, 'r') as file:
            return file.read().strip()
    return None
def download_update(download_url, output_path):
    try:
        response = requests.get(download_url, stream=True)
        response.raise_for_status()
        os.makedirs(UPDATE_FOLDER, exist_ok=True)
        with open(output_path, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)
        return output_path
    except Exception as e:
        print(f"{Fore.RED}Error downloading the update: {e}{Style.RESET_ALL}")
        return None
def apply_update(new_file, current_file):
    try:
        batch_script = f"""
        @echo off
        echo Waiting for the main program to close...
        ping 127.0.1.1 -n 5 > nul
        move /Y "{new_file}" "{current_file}"
        start "" "pyhton {current_file}"
        exit
        """
        batch_file = os.path.join(UPDATE_FOLDER, 'update.bat')
        with open(batch_file, 'w') as f:
            f.write(batch_script)
        subprocess.Popen(batch_file, shell=True)
        print(f"Update script created. The program will now update and restart.")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}Error applying the update: {e}{Style.RESET_ALL}")
def main():
    while True:
        try:
            clear_screen()
            display_header()
            apikey = load_api_key()
            if not apikey:
                apikey = getpass.getpass("Enter API key: ")
            user, valid = validate_api_key(apikey)
            if not valid:
                print("Invalid API key. Redirecting to registration page...")
                open_registration_page()
                continue
            print(Fore.GREEN + "╭─" + Fore.GREEN + "「" + Fore.CYAN + f" Welcome {user} " + Fore.GREEN + "」" + Style.RESET_ALL)
            print(Fore.GREEN + "│" + Style.RESET_ALL + " 1. Reverse IP")
            print(Fore.GREEN + "│" + Style.RESET_ALL + " 2. Subdomain Finder")
            print(Fore.GREEN + "│" + Style.RESET_ALL + " 3. Discovery Domain Engine")
            print(Fore.GREEN + "│" + Style.RESET_ALL + " 4. Grab by Date")
            print(Fore.GREEN + "│" + Style.RESET_ALL + " 5. Domain to IP")
            print(Fore.GREEN + "│" + Style.RESET_ALL + " 6. Remove Duplicates list")
            print(Fore.GREEN + "│" + Style.RESET_ALL + " 7. Check for Updates")
            print(Fore.GREEN + "╰─────────────────────────" + Style.RESET_ALL)
            while True:
                choice_input = input("$ choose: ").strip()
                if choice_input.isdigit():
                    choice = int(choice_input)
                    break
                else:
                    print(f"{Fore.RED}Invalid input. Please enter a number between 1 and 7.{Style.RESET_ALL}")
            if choice == 1:
                print(Fore.GREEN + "[ ReverseIP started... ]" + Style.RESET_ALL)
                input_list = input("$ give me your file list: ").strip()
                filter_domain = input("$ filter domain [y/n]: ").strip().lower()
                domain_filter = None
                if filter_domain == 'y':
                    domain_filter = input("$ domain yang akan di ambil [ ex : .id ]: ").strip()
                auto_domain_to_ip = input("$ auto domain to ip [ Y/N ]: ").strip().lower()
                output_file = input("$ save to: ").strip()
                with open(input_list, 'r') as f:
                    items = [item.strip() for item in f.readlines()]
                def process_and_reverse(domain_or_ip):
                    if auto_domain_to_ip == 'y':
                        ip = domain_to_ip(domain_or_ip)
                        if ip:
                            reverse_ip(ip, apikey, output_file, domain_filter)
                    else:
                        reverse_ip(domain_or_ip, apikey, output_file, domain_filter)
                with ThreadPoolExecutor(max_workers=15) as executor:
                    executor.map(process_and_reverse, items)
            elif choice == 2:
                print(Fore.GREEN + "[ Subdomain finder started... ] " + Style.RESET_ALL)
                input_list = input("$ give me your file list: ")
                output_file = input("$ save to: ")
                with open(input_list, 'r') as f:
                    items = [item.strip() for item in f.readlines()]
                with ThreadPoolExecutor(max_workers=30) as executor:
                    for domain in items:
                        executor.submit(subdomain_finder, domain, apikey, output_file)
                remove_duplicates(output_file)
            elif choice == 3:
                discovery_domain_engine(apikey)
            elif choice == 4:
                print(Fore.GREEN + "[ Grab by date started ] ..." + Style.RESET_ALL)
                date = input("$ Enter date (YYYY-MM-DD): ")
                start_page = int(input("$ Page [ start from ]: "))
                end_page = int(input("$ to page: "))
                output_file = input("$ save to: ")
                thread_count = int(input("$ enter thread count: "))
                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    for page in range(start_page, end_page + 1):
                        executor.submit(grab_by_date, page, apikey, date, output_file)
            elif choice == 5:
                domain_to_ip_tool()
            elif choice == 6:
                output_file = input("$ Enter the output file to clean duplicates: ")
                remove_duplicates(output_file)
            elif choice == 7:
                check_for_updates()
            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")
            input(f"\n{Fore.GREEN}Task completed. Press Enter to return to the main menu.{Style.RESET_ALL}")
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Process interrupted by user (Ctrl+C). Exiting...{Style.RESET_ALL}")
            sys.exit(0)
def clear_screen():
    if os.name == 'nt':
        os.system('cls')
    else:
        os.system('clear')
def display_header():
    print(Fore.CYAN + '░██████╗██╗░░░██╗██████╗░██████╗░███████╗██╗░░░██╗')
    print(Fore.CYAN + '██╔════╝██║░░░██║██╔══██╗██╔══██╗██╔════╝██║░░░██║')
    print(Fore.CYAN + '╚█████╗░██║░░░██║██████╦╝██████╔╝█████╗░░╚██╗░██╔╝')
    print(Fore.CYAN + '░╚═══██╗██║░░░██║██╔══██╗██╔══██╗██╔══╝░░░╚████╔╝░')
    print(Fore.CYAN + '██████╔╝╚██████╔╝██████╦╝██║░░██║███████╗░░╚██╔╝░░')
    print(Fore.CYAN + '╚═════╝░╚═════╝░╚═════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░')
    print(Fore.WHITE + " - developed by Eclipse Security Labs")
    print(Fore.WHITE + " - website : https://eclipsesec.tech/")
    print(Fore.GREEN + " - version : 1.5.2")
    print(Style.RESET_ALL)
def open_registration_page():
    registration_url = "https://eclipsesec.tech/register"
    try:
        webbrowser.open(registration_url)
        print(f"{Fore.GREEN}Opening registration page: {registration_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to open registration page: {e}{Style.RESET_ALL}")
if __name__ == "__main__":
    main()