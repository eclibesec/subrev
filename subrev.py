import os
import sys
import time
import json
import socket
import requests
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from colorama import init, Fore, Style
import getpass
import webbrowser

init()
# List of required modules
REQUIRED_MODULES = [
    'requests',
    'colorama'
]

# Function to check and install missing modules
def install_missing_modules():
    for module in REQUIRED_MODULES:
        try:
            __import__(module)  # Try importing the module
        except ImportError:
            print(f"Module '{module}' not found. Installing...")
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', module])

# Call the function to check and install required modules
install_missing_modules()
# Global file lock to prevent simultaneous write access by threads
file_lock = threading.Lock()

CONFIG_PATH = 'subrev/config.json'

# Ensure subrev/ folder exists
os.makedirs('subrev', exist_ok=True)

# Prefixes to filter subdomains
FILTERED_PREFIXES = ['*.', 'www.', 'webmail.', 'cpanel.', 'cpcalendars.', 'cpcontacts.', 'webdisk.', 'mail.', 'whm.', 'autodiscover.']

# Function to clean subdomains by removing filtered prefixes
def clean_domain(domain):
    cleaned_domain = domain
    for prefix in FILTERED_PREFIXES:
        if cleaned_domain.startswith(prefix):
            cleaned_domain = cleaned_domain[len(prefix):]
    return cleaned_domain

# Function to remove duplicates from output file
def remove_duplicates(output_file):
    try:
        with open(output_file, "r", encoding="utf-8") as file:
            lines = file.readlines()

        # Remove duplicates
        unique_lines = list(set(line.strip() for line in lines))

        # Overwrite the file with unique lines
        with open(output_file, "w", encoding="utf-8") as file:
            for line in sorted(unique_lines):
                file.write(line + "\n")

        print(f"{Fore.GREEN}Duplicates removed from '{output_file}'.{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error while removing duplicates: {e}{Style.RESET_ALL}")

# Function to validate API key and save it if valid
def validate_api_key(apikey):
    url = f"https://eclipsesec.tech/api/?apikey={apikey}&validate=true"
    for retries in range(10):
        try:
            response = requests.get(url)
            response.raise_for_status()
            body = response.json()
            if body.get('status') == "valid":
                save_api_key(apikey)  # Save valid API key to config.json
                return body.get('user'), True
        except Exception as e:
            log_error("API key validation failed", e)
            time.sleep(2)
    
    # If validation fails, prompt the user for a new API key
    return "", False

# Save API key to config.json
def save_api_key(apikey):
    config_data = {"apikey": apikey}
    with open(CONFIG_PATH, 'w', encoding='utf-8') as config_file:
        json.dump(config_data, config_file)
    print(f"{Fore.GREEN}API key saved to {CONFIG_PATH}{Style.RESET_ALL}")

# Load API key from config.json
def load_api_key():
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, 'r', encoding='utf-8') as config_file:
            config_data = json.load(config_file)
            return config_data.get('apikey', None)
    return None

# Function to open registration page in a browser
def open_registration_page():
    registration_url = "https://eclipsesec.tech/register"
    try:
        webbrowser.open(registration_url)
        print(f"{Fore.GREEN}Opening registration page: {registration_url}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Failed to open registration page: {e}{Style.RESET_ALL}")

# Logging error
def log_error(message, err):
    if err:
        print(Fore.RED + f"ERROR: {message} - {err}" + Style.RESET_ALL)

# Function for Reverse IP scanning with infinite retry
def reverse_ip(ip, apikey, output_file):
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
            if response.status_code == 500:
                print(f"{Fore.YELLOW}500 Internal Server Error. Retrying...{Style.RESET_ALL}")
                time.sleep(5)
            else:
                log_error("Reverse IP scanning failed", http_err)
                break
        except Exception as e:
            log_error("An error occurred during Reverse IP scanning", e)
            break

# Function for Subdomain Finder with infinite retry and filtering
def subdomain_finder(domain, apikey, output_file):
    url = f"https://eclipsesec.tech/api/?subdomain={domain}&apikey={apikey}"
    while True:
        try:
            response = requests.get(url)
            response.raise_for_status()
            body = response.json()
            if body.get('subdomains'):
                print(f"[{Fore.GREEN}extracting {domain} -> {len(body['subdomains'])} subdomains found{Style.RESET_ALL}]")
                with file_lock, open(output_file, "a") as f:
                    for subdomain in body['subdomains']:
                        cleaned_subdomain = clean_domain(subdomain)
                        f.write(cleaned_subdomain + "\n")
                break
        except requests.exceptions.HTTPError as http_err:
            if response.status_code == 500:
                print(f"{Fore.YELLOW}500 Internal Server Error. Retrying...{Style.RESET_ALL}")
                time.sleep(5)
            else:
                log_error("Subdomain Finder failed", http_err)
                break
        except Exception as e:
            log_error("An error occurred during Subdomain Finder", e)
            break

# Function to grab domains by date with infinite retry
def grab_by_date(page, apikey, date, output_file):
    url = f"https://eclipsesec.tech/api/?bydate={date}&page={page}&apikey={apikey}"
    while True:
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
            if response.status_code == 500:
                print(f"{Fore.YELLOW}500 Internal Server Error. Retrying...{Style.RESET_ALL}")
                time.sleep(5)
            else:
                log_error("Grab by date failed", http_err)
                break
        except Exception as e:
            log_error("An error occurred during Grab by Date", e)
            break

# Function to convert domain to IP
def domain_to_ip(domain_name):
    if len(domain_name) > 253 or len(domain_name) == 0:
        return None
    try:
        domain_name.encode('idna')
        ip_address = socket.gethostbyname(domain_name)
        return ip_address
    except (socket.gaierror, UnicodeError):
        return None

# Domain to IP tool
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
                    f.write(f"{domain} -> {ip_address}\n")
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

# Main function with API key loading and saving
def main():
    while True:
        try:
            clear_screen()
            display_header()
            
            # Load API key from config file if it exists
            apikey = load_api_key()
            if not apikey:
                apikey = getpass.getpass("Enter API key: ")
            
            user, valid = validate_api_key(apikey)
            if not valid:
                print("Invalid API key. Redirecting to registration page...")
                open_registration_page()
                continue  # Restart loop to prompt for API key again
            
            print(Fore.GREEN + f"[ Welcome {user} ]" + Style.RESET_ALL)
            print("1. Reverse IP")
            print("2. Subdomain Finder (with filter)")
            print("3. Grab by Date")
            print("4. Domain to IP")
            print("5. Remove Duplicates from Output")
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

            else:
                print(f"{Fore.RED}Invalid choice. Please select a valid option.{Style.RESET_ALL}")

            # Return to the main menu after task completion
            input(f"\n{Fore.GREEN}Task completed. Press Enter to return to the main menu.{Style.RESET_ALL}")

        except KeyboardInterrupt:
            print(f"\n{Fore.RED}Process interrupted by user (Ctrl+C). Exiting...{Style.RESET_ALL}")
            sys.exit(0)

# Helper functions to clear the screen and display the header
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

if __name__ == "__main__":
    main()
