#!/usr/bin/env python3

import sys
import urllib.request
import urllib.parse
import re
import asyncio

print("""

\033[1;35m█▀ █░█ █▄▄ █▀▄ █▀█ █▀▄▀█ ▄▀█ █ █▄░█   █▀ █▀▀ ▄▀█ █▄░█ █▄░█ █▀▀ █▀█
\033[1;39m▄█ █▄█ █▄█ █▄▀ █▄█ █░▀░█ █▀█ █ █░▀█   ▄█ █▄▄ █▀█ █░▀█ █░▀█ ██▄ █▀▄\033[1;35m
                                            - developed by NowMeee 
                        
""")

async def fetch_certificates(domain, file_handle):
    excluded_subdomains = {'www.', 'cpanel.', 'cpcalendars.', 'webdisk.', 'webmail.', '*.'}
    try:
        await asyncio.sleep(0)  # Small delay to allow other tasks to run
        with urllib.request.urlopen('https://crt.sh/?q=' + urllib.parse.quote('%.' + domain)) as r:
            code = r.read().decode('utf-8')
            matches = re.findall(r'<tr>(?:\s|\S)*?href="\?id=[0-9]+?"(?:\s|\S)*?<td>([_a-zA-Z0-9.-]+?\.' + re.escape(domain) + ')</td>(?:\s|\S)*?</tr>', code, re.IGNORECASE)
            found_domains = set()
            
            for match in matches:
                match = match.split('@')[-1]
                if match not in found_domains and not any(match.startswith(sub) for sub in excluded_subdomains):
                    found_domains.add(match)
                    file_handle.write(match + '\n')
                    print(match)
    except urllib.error.HTTPError as error:
        if error.code in [502, 503]:
            print(f"{error.code} Error: Server temporarily unavailable for {domain}. Retrying in 1 second...")
            await asyncio.sleep(1)
            await fetch_certificates(domain, file_handle)
        else:
            print(f"Error fetching data for {domain}: {error}")

async def main():
    try:
        input_file = input('$ List domain file path: ')
        output_file = input('$ Output file path: ')

        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]

        with open(output_file, 'w') as file_handle:
            for domain in domains:
                await fetch_certificates(domain, file_handle)

        print(f"Data has been saved to {output_file}")
    except Exception as e:
        print('Error:', str(e))
    finally:
        sys.exit(0)

# Entry point of the script
if __name__ == "__main__":
    asyncio.run(main())
