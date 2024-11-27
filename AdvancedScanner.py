import requests
from bs4 import BeautifulSoup
import whois
from urllib.parse import urljoin, urlparse
import json
from colorama import Fore, Style, init
import time
import socket
import sys

# Initialize colorama for colorful output
init(autoreset=True)

# Loading animation
def loading_screen(message, duration=3):
    print(f"{Fore.CYAN}{message}")
    for _ in range(duration):
        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(1)
    print("\n")

def validate_url(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url
    return url

def save_results_to_file(data, filename, file_format="txt"):
    if file_format == "json":
        with open(filename, "w") as json_file:
            json.dump(data, json_file, indent=4)
        print(f"{Fore.GREEN}Results saved to {filename} (JSON format).")
    elif file_format == "txt":
        with open(filename, "w") as txt_file:
            for key, value in data.items():
                txt_file.write(f"{key}:\n")
                txt_file.write(f"{json.dumps(value, indent=4)}\n\n")
        print(f"{Fore.GREEN}Results saved to {filename} (TXT format).")
    else:
        print(f"{Fore.RED}Unsupported file format: {file_format}")

# Perform a port scan using the custom socket-based function
def perform_port_scan(hostname, start_port=1, end_port=1024):
    """
    Eine einfache Port-Scan-Funktion, die offene Ports auf einem Host überprüft.
    """
    open_ports = []
    print(f"\n{Fore.YELLOW}{'-'*20} Starting Port Scan {'-'*20}")
    print(f"Scanning ports {start_port}-{end_port} on {hostname}...\n")

    for port in range(start_port, end_port + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)  # Setzt ein Timeout von 1 Sekunde
            result = sock.connect_ex((hostname, port))
            if result == 0:  # Port ist offen
                print(f"  {Fore.LIGHTGREEN_EX}Port {port} is open.")
                open_ports.append(port)

    print(f"\n{Fore.GREEN}Scanning completed. Open ports: {open_ports}")
    return open_ports

def scan_website(url):
    # Initialization screen
    loading_screen("Initializing Advanced Website and Port Scanner", 3)

    url = validate_url(url)
    print(f"{Fore.BLUE}{'-'*40}")
    print(f"Scanning Website: {url}")
    print(f"{'-'*40}\n")

    # Initialize results dictionary
    scan_results = {"url": url, "links": {}, "forms": [], "whois": {}, "ports": []}

    # Make a request to the website
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        print(f"{Fore.GREEN}✅ Website is reachable")
    except requests.RequestException as e:
        print(f"{Fore.RED}❌ Website is not reachable. Error: {e}")
        return

    # Parse the HTML content of the website
    html_content = response.text
    soup = BeautifulSoup(html_content, 'html.parser')

    # Find and categorize links
    print(f"\n{Fore.YELLOW}{'-'*20} Links Found {'-'*20}")
    internal_links = set()
    external_links = set()
    for link in soup.find_all('a', href=True):
        href = urljoin(url, link['href'])
        if urlparse(href).netloc == urlparse(url).netloc:
            internal_links.add(href)
        else:
            external_links.add(href)

    scan_results["links"]["internal"] = list(internal_links)
    scan_results["links"]["external"] = list(external_links)

    print(f"{Fore.YELLOW}Internal Links:")
    for link in internal_links:
        print(f"  {Fore.LIGHTGREEN_EX}{link}")

    print(f"\n{Fore.CYAN}External Links:")
    for link in external_links:
        print(f"  {Fore.LIGHTBLUE_EX}{link}")

    # Analyze forms on the website
    print(f"\n{Fore.MAGENTA}{'-'*20} Forms Found {'-'*20}")
    forms = soup.find_all('form')
    for form in forms:
        method = form.get('method', 'GET').upper()
        action = form.get('action', '')
        action_url = urljoin(url, action)
        form_info = {"method": method, "action": action_url}
        scan_results["forms"].append(form_info)
        print(f"  {Fore.MAGENTA}Form - Method: {method}, Action: {action_url}")

        # Perform a WHOIS lookup
        print(f"\n{Fore.CYAN}{'-'*20} Whois Information {'-'*20}")
        try:
            domain_info = whois.whois(urlparse(url).netloc)
            scan_results["whois"] = {
                "domain": domain_info.domain_name,
                "registrar": domain_info.registrar,
                "creation_date": str(domain_info.creation_date) if domain_info.creation_date else "N/A",
                "expiration_date": str(domain_info.expiration_date) if domain_info.expiration_date else "N/A"
            }
            print(f"  Domain: {Fore.LIGHTYELLOW_EX}{domain_info.domain_name}")
            print(f"  Registrar: {Fore.LIGHTYELLOW_EX}{domain_info.registrar}")
            print(f"  Creation Date: {Fore.LIGHTYELLOW_EX}{scan_results['whois']['creation_date']}")
            print(f"  Expiration Date: {Fore.LIGHTYELLOW_EX}{scan_results['whois']['expiration_date']}")
        except Exception as e:
            print(f"{Fore.RED}❌ Whois lookup failed. Error: {e}")

    # Ask the user whether they want to scan all ports
    scan_all_ports = input(f"{Fore.YELLOW}Do you want to scan all ports (1-65535)? This may take a long time. (yes/no): ").strip().lower()
    
    # Decide the port range based on user input
    if scan_all_ports in ["yes", "y"]:
        start_port = 1
        end_port = 65535
    else:
        start_port = 1
        end_port = 1024

    # Perform a port scan using the custom socket-based function
    hostname = urlparse(url).hostname
    if hostname:
        open_ports = perform_port_scan(hostname, start_port, end_port)
        scan_results["ports"] = open_ports
    else:
        print(f"{Fore.RED}❌ Unable to resolve hostname for the URL.")

    # Ask the user to save the results
    save_option = input(f"\n{Fore.YELLOW}Do you want to save the results? (yes/no): ").strip().lower()
    if save_option in ["yes", "y"]:
        filename = input("Enter the filename (without extension): ").strip()
        file_format = input("Enter the format (txt/json): ").strip().lower()
        save_results_to_file(scan_results, f"{filename}.{file_format}", file_format)

    # Completion message
    print(f"\n{Fore.GREEN}Thanks for using! Please give us a ⭐ on GitHub!")

# Example usage
if __name__ == "__main__":
    print(f"{Fore.LIGHTCYAN_EX}Welcome to the Advanced Website and Port Scanner!")
    target_url = input(f"{Fore.YELLOW}Enter the website URL to scan: ").strip()
    scan_website(target_url)

    # Completion message
    print(f"\n{Fore.GREEN}Thanks for using! Please give us a ⭐ on GitHub!")

    # Halt the script from closing immediately
    input(f"\n{Fore.CYAN}Press Enter to exit...")
