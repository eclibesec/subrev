import os
import sys
import requests
import subprocess
import shutil
import zipfile
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from time import sleep
from colorama import init, Fore, Style
import getpass
import webbrowser
import json

init()

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
    FILTERED_PREFIXES = ['www.', 'webmail.', 'cpanel.', 'cpcalendars.', 'cpcontacts.', 'webdisk.', 'mail.', 'whm.', 'autodiscover.']
    cleaned_domain = domain
    for prefix in FILTERED_PREFIXES:
        if cleaned_domain.startswith(prefix):
            cleaned_domain = cleaned_domain[len(prefix):]
    return cleaned_domain
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
    
    print(f"{Fore.GREEN}Success login{Style.RESET_ALL}")
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
    try:
        response = requests.get(url)
        response.raise_for_status()
        body = response.json()
        with open("debug.txt", "a", encoding="utf-8") as debug_file:
            debug_file.write(f"API Response: {body}\n")
        
        if body.get('status') == "valid":
            save_api_key(apikey)
            return body.get('user'), True
        else:
            with open("debug.txt", "a", encoding="utf-8") as debug_file:
                debug_file.write(f"Invalid API key: {body.get('message', 'Unknown error')}\n")
            print(f"{Fore.RED}Invalid API key: {body.get('message', 'Unknown error')}{Style.RESET_ALL}")
    except Exception as e:
        with open("debug.txt", "a", encoding="utf-8") as debug_file:
            debug_file.write(f"Error during API key validation: {str(e)}\n")
        print(f"{Fore.RED}API key validation failed: {e}{Style.RESET_ALL}")
    return "", False
def reverse_ip(ip, apikey, output_file, bad_domains_file='bad_domains.txt'):
    url = f"https://eclipsesec.tech/api/?reverseip={ip}&apikey={apikey}"
    while True:
        try:
            response = requests.get(url)
            response.raise_for_status()
            body = response.json()
            if body.get('domains'):
                print(f"[{Fore.GREEN}reversing {ip} -> {len(body['domains'])} domains found{Style.RESET_ALL}]")
                with file_lock, open(output_file, "a") as f:
                    for domain in body['domains']:
                        f.write(domain + "\n")
                break
        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 502:
                print(f"{Fore.YELLOW}[ Retrying ] -> {ip}{Style.RESET_ALL}")
                sleep(1)
            elif response.status_code == 500:
                print(f"{Fore.RED}[Bad Ip] -> {ip}{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Reverse IP scanning failed: {http_err}{Style.RESET_ALL}")
                break
        except Exception as e:
            print(f"{Fore.RED}Error during Reverse IP scanning: {e}{Style.RESET_ALL}")
            break

def subdomain_finder(domain, apikey, output_file, bad_domains_file='bad_domains.txt'):
    url = f"https://eclipsesec.tech/api/?subdomain={domain}&apikey={apikey}"
    while True:
        try:
            response = requests.get(url)
            response.raise_for_status()
            body = response.json()
            if not body.get('subdomains'):
                print(f"{Fore.YELLOW}[Bad] -> {domain}{Style.RESET_ALL}")
                break  
            if body.get('subdomains'):
                print(f"[{Fore.GREEN}extracting {domain}] -> [{len(body['subdomains'])} subdomains]{Style.RESET_ALL}]")
                with file_lock, open(output_file, "a") as f:
                    for subdomain in body['subdomains']:
                        cleaned_subdomain = clean_domain(subdomain)
                        f.write(cleaned_subdomain + "\n")
                break
        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 502:
                print(f"{Fore.YELLOW}[ retrying ] -> {domain}{Style.RESET_ALL}")
                sleep(1)
            elif response.status_code == 500:
                print(f"{Fore.RED}[ No subdomains found ] -> {domain} {Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Subdomain Finder failed: {http_err}{Style.RESET_ALL}")
                break
        except Exception as e:
            print(f"{Fore.RED}Error during Subdomain Finder: {e}{Style.RESET_ALL}")
            break

def grab_by_date(page, apikey, date, output_file, bad_domains_file='bad_domains.txt'):
    url = f"https://eclipsesec.tech/api/?bydate={date}&page={page}&apikey={apikey}"
    while True:  # Keep retrying indefinitely
        try:
            response = requests.get(url)
            response.raise_for_status()
            body = response.json()
            if body.get('domains'):
                print(f"page [{page}] -> domains found [{len(body['domains'])}]")
                with file_lock, open(output_file, "a") as f:
                    for domain in body['domains']:
                        f.write(domain + "\n")
                break
        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 502:
                print(f"{Fore.YELLOW}Retrying...{page}.{Style.RESET_ALL}")
                sleep(1)
            elif response.status_code == 500:
                print(f"{Fore.RED}{page} NO DOMAINS{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Grab by date failed: {http_err}{Style.RESET_ALL}")
                break
        except Exception as e:
            print(f"{Fore.RED}Error during Grab by Date: {e}{Style.RESET_ALL}")
            break

def domain_to_ip(domain_name):
    if len(domain_name) > 253 or len(domain_name) == 0:
        return None
    try:
        domain_name.encode('idna')
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except (socket.gaierror, UnicodeError):
        return None
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
        start "" "{current_file}"
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
            print(Fore.GREEN + f"[ Welcome {user} ]" + Style.RESET_ALL)
            print("1. Reverse IP ( only ip )")
            print("2. Subdomain Finder (auto filter .cpanel etc..")
            print("3. Grab by Date")
            print("4. Domain to IP")
            print("5. Remove Duplicates list")
            print("6. Check for Updates")
            choice = int(input("$ choose: "))
            if choice == 1 or choice == 2:
                input_list = input("$ give me your file list: ")
                output_file = input("$ save to: ")
                thread_count = int(input("$ enter thread count: "))
                with open(input_list, 'r') as f:
                    items = [item.strip() for item in f.readlines()]
                if choice == 1:
                    with ThreadPoolExecutor(max_workers=thread_count) as executor:
                        for ip in items:
                            executor.submit(reverse_ip, ip, apikey, output_file)
                elif choice == 2:
                    with ThreadPoolExecutor(max_workers=thread_count) as executor:
                        for domain in items:
                            executor.submit(subdomain_finder, domain, apikey, output_file)
            elif choice == 3:
                date = input("$ Enter date (YYYY-MM-DD): ")
                start_page = int(input("$ Page [ start from ]: "))
                end_page = int(input("$ to page: "))
                output_file = input("$ save to: ")
                thread_count = int(input("$ enter thread count: "))
                with ThreadPoolExecutor(max_workers=thread_count) as executor:
                    for page in range(start_page, end_page + 1):
                        executor.submit(grab_by_date, page, apikey, date, output_file)
            elif choice == 4:
                domain_to_ip_tool()
            elif choice == 5:
                output_file = input("$ Enter the output file to clean duplicates: ")
                remove_duplicates(output_file)
            elif choice == 6:
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
