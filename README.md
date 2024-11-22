# Subrev Tools

![SubRev](https://i.ibb.co/WyK8cHQ/image.png)

**Subrev Tools** is a multifunctional tool designed to handle various tasks related to domains, IPs, and subdomains. This tool can perform Reverse IP lookups, find subdomains, retrieve domain data based on date, convert domains to IPs, and remove duplicates from the output file. The API key only needs to be entered once and will be saved automatically for future use.

## Features

- **Reverse IP**: Processes a list of IP addresses to find all related domains.
- **Subdomain Finder**: Finds subdomains from a given list of domains.
- **Discocvery domain grabber** : [ NEW ]
- **Grab by Date**: Retrieves a list of domains found on a specific date.
- **Domain to IP**: Converts a list of domains to their corresponding IP addresses.
- **Remove Duplicates**: Removes duplicate entries from the output file.
- **API Key Persistence**: The API key only needs to be entered once. It will be saved in a `config.json` file and automatically loaded in the future.
- **Auto-Install Modules**: Automatically installs any missing Python modules (e.g., `requests`, `colorama`). If the required modules are already installed, the tool skips installation.
- **Auto update**: Automatically update python & exe file
## Requirements

- **Python**: Make sure you have Python 3.x installed on your system.

The required modules will be auto-installed if they are missing. These modules include:

- `requests`
- `colorama`

## Installation

1. Clone this repository to your local directory:

   ```
   git clone https://github.com/eclibesec/subrev
2. Navigate to the project directory:
   ```
   cd subrev
3. Install the required libraries:
   ```
   pip install -r requirements.txt
## Usage
1. Running the Tool: Run the tool using the following command:
   ```
   python subrev.py
2. main menu
- **Once you run the tool, you will see a menu with several options:**
  - **Reverse IP**
  - **Subdomain Finder**
  - **Discovery Domain Engine**
  - **Grab by Date**
  - **Domain to IP**
  - **Remove Duplicates**
  - **auto update**
3. APIKEY:
   - **On first use, the tool will prompt you to enter the API key. This key will be saved in the subrev/config.json file.**
   - **On subsequent runs, the API key will be automatically loaded.**

## Example Usage
- **Reverse IP: You can provide a list of IP addresses to be processed, and the tool will find all domains associated with the given IPs.**
- **Subdomain Finder: Provide a list of domains, and the tool will find all subdomains associated with the given domains.**
- **Grab by Date: Enter a specific date, and the tool will retrieve domains found by the API on that date.**
- **Domain to IP: Provide a list of domains to convert them into their corresponding IP addresses.**
- **Remove Duplicates: Use this feature to clean up your output file by removing duplicate entries.**

## Folder Structure
  ```
├── subrev/
│   └── config.json     # Configuration file for storing the API key
├── requirements.txt    # Python dependencies file
└── subrev.py           # Main tool file
