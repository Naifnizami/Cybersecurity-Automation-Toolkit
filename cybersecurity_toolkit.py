import subprocess
import platform
import re
import nmap
import json
import csv
import os
import argparse
import logging
import sys
from fpdf import FPDF
from tabulate import tabulate

# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    filename='scan.log',
                    filemode='w')

def sanitize_input(prompt, pattern="^[a-zA-Z0-9_.-]+$", error_msg="Invalid input. Use only letters, numbers, '-', '_', and '.'."):
    """Sanitizes user input based on a regex pattern."""
    while True:
        user_input = input(prompt).strip()
        if user_input and re.match(pattern, user_input):
            return user_input
        print(f"[✗] {error_msg} Please try again.")
        logging.warning(f"Invalid input received: {user_input}")


def detect_subnet():
    """Detect the correct subnet dynamically for all private IP ranges."""
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("ipconfig", shell=True, universal_newlines=True)
            match = re.search(r"IPv4 Address.*?: (\d+\.\d+\.\d+)\.\d+", output)
        else:  # Linux/macOS
            output = subprocess.check_output("ip route", shell=True, universal_newlines=True)
            match = re.search(r"src (\d+\.\d+\.\d+)\.\d+", output)

        if match:
            base_ip = match.group(1)
            subnet = base_ip + ".0/24"
            print(f"\n[✓] Detected Network Subnet: {subnet}")
            return subnet
        else:
            print("[✗] Could not detect subnet. Using default 192.168.1.0/24")
            return "192.168.1.0/24"
    except Exception as e:
        print(f"[✗] Error detecting subnet: {e}")
        logging.error(f"Error detecting subnet: {e}", exc_info=True)
        return "192.168.1.0/24"

def find_live_hosts(network_range):
    """Uses a fast Nmap scan to detect live hosts."""
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=network_range, arguments="-sn -T4")  # Fast host discovery
        live_hosts = [host for host in nm.all_hosts()]
        print(f"\n[✓] Live Hosts Found: {', '.join(live_hosts)}")
        return live_hosts
    except Exception as e:
        print(f"[✗] Error during host discovery: {e}")
        logging.error(f"Error during host discovery: {e}", exc_info=True)
        return []

def check_unwanted_software(installed_software):
    """Identify software that is unnecessary for a corporate environment."""
    unwanted = {"Spotify", "iTunes", "Games", "Netflix", "VLC"}
    return [app for app in installed_software if app in unwanted]

def check_outdated_software(installed_software):
    """Identify outdated or potentially pirated software."""
    outdated_versions = {"Microsoft Office 2016", "Windows 7", "Adobe Photoshop CS6"}
    pirated_software = []
    return {
        "Outdated": [app for app in installed_software if app in outdated_versions],
        "Pirated": pirated_software
    }

def manual_hardware_and_software_input(host):
    """Manually input hardware details and software audit."""
    print(f"\n[!] Please manually check the system {host} and enter the details below.")

    system_name = sanitize_input("System Name (e.g., PC-1234, Server-01): ")
    os_version = sanitize_input("Operating System (e.g., Windows 10 Pro, Ubuntu 22.04): ")
    cpu_info = sanitize_input("CPU (e.g., Intel Core i7-10700K, AMD Ryzen 9 5900X): ")
    ram_info = sanitize_input("RAM (e.g., 16GB, 32GB DDR4): ")
    disk_info = sanitize_input("Disk Model/Size (e.g., Samsung SSD 1TB, HDD 500GB): ")

    print("\n[!] Enter installed software applications (type 'done' when finished):")
    installed_software = []
    while True:
        software = sanitize_input("Installed Software: ", pattern="^[a-zA-Z0-9 ]+$", error_msg="Invalid software name. Use only letters, numbers, and spaces.")
        if software.lower() == 'done':
            break
        installed_software.append(software)

    unwanted_software = check_unwanted_software(installed_software)
    outdated_software = check_outdated_software(installed_software)

    return {
        "System Name": system_name,
        "OS": os_version,
        "CPU": cpu_info,
        "RAM": ram_info,
        "Disk": disk_info,
        "Installed Software": installed_software,
        "Unwanted Software": unwanted_software,
        "Outdated/Pirated Software": outdated_software
    }

def scan_network(host, nmap_arguments):
    """Scans a host using Nmap with specified arguments."""
    nm = nmap.PortScanner()
    try:
        print(f"\n[✓] Scanning {host} with arguments: {nmap_arguments}...")
        nm.scan(hosts=host, arguments=nmap_arguments)  # Changed
        if host not in nm.all_hosts():
            print(f"[⚠] Skipping {host}: No scan data returned.")
            return {}

        scan_results = {
            "hostname": nm[host].hostname() if nm[host].hostname() else "Unknown",
            "state": nm[host].state(),
            "protocols": {}
        }

        for proto in nm[host].all_protocols():
            scan_results["protocols"][proto] = {}
            for port in nm[host][proto]:
                scan_results["protocols"][proto][port] = {
                    "state": nm[host][proto][port]['state'],
                    "service": nm[host][proto][port].get("name", "Unknown"),
                    "version": nm[host][proto][port].get("version", "Unknown"),
                }
        return scan_results

    except Exception as e:
        print(f"[✗] Error during Nmap scan of {host}: {e}")
        logging.error(f"Error during Nmap scan of {host}: {e}", exc_info=True)
        return {}


def analyze_vulnerabilities(scan_results):
    """Analyzes scan results and identifies critical vulnerabilities (expandable)."""
    vulnerabilities = {}
    for host, data in scan_results.items():
        vulnerabilities[host] = []

        for proto, ports in data.get("protocols", {}).items():
            for port, details in ports.items():
                service = details["service"].lower()
                version = details["version"]
                # Add rules as required

                if service in ["telnet", "ftp", "smb"]:
                    vulnerabilities[host].append(f"Unsecure service {details['service']} running on port {port}")
                if service == "http" and port == 80:
                    vulnerabilities[host].append(f"HTTP running on standard port.") #Just an example
                if version != "Unknown" : #Just example that could be added if you integrated with a CVE db.
                     pass#Implement if version is running CVE scan with associated databases (ex. Vulners library)

    return vulnerabilities


def display_results(scan_results, vulnerabilities):
    """Displays scan results in a tabular format."""
    table = []
    for host, data in scan_results.items():
        for proto, ports in data.get("protocols", {}).items():
            for port, details in ports.items():
                table.append([host, port, details["service"], details["state"], ", ".join(vulnerabilities.get(host, []))])

    print(tabulate(table, headers=["Host", "Port", "Service", "State", "Vulnerabilities"], tablefmt="grid"))

def get_report_directory():
    """Prompts the user to select an existing directory for saving reports or creates a new one if the user requests."""
    while True:
        report_path = input("Enter the full directory path to save reports (or type 'new' to create a new directory): ").strip()

        if report_path.lower() == 'new':
            new_dir_name = input("Enter the name for the new directory: ").strip()
            report_path = os.path.join(os.getcwd(), new_dir_name)  # Create it in the current directory
            try:
                os.makedirs(report_path, exist_ok=True)  # Create the directory, no error if it exists
                print(f"[✓] Created new directory: {report_path}")
                return report_path
            except OSError as e:
                print(f"[✗] Error creating directory: {e}. Please try again.")
                continue

        if os.path.exists(report_path) and os.path.isdir(report_path):
            return report_path  # ✅ Valid existing directory → Proceed
        else:
            print("[✗] Invalid directory. Please enter a valid existing path.")  # ❌ Invalid path → Retry


def get_report_filename():
    """Prompts the user for a valid filename, allowing only letters and numbers."""
    while True:
        filename = input("Enter a filename (only letters and numbers, no special characters): ").strip()
        if filename.isalnum():  # Ensures only letters and numbers
            return filename
        print("[✗] Invalid filename. Use only letters and numbers.")


def generate_report(scan_results, vulnerabilities, report_dir, filename):
    """Generates reports in JSON, CSV, and PDF formats in the user-specified directory."""

    json_path = os.path.join(report_dir, f"{filename}.json")
    csv_path = os.path.join(report_dir, f"{filename}.csv")
    pdf_path = os.path.join(report_dir, f"{filename}.pdf")

    try:
        with open(json_path, "w") as json_file:
            json.dump(scan_results, json_file, indent=4)
        print(f"[✓] JSON report saved to: {json_path}")
        logging.info(f"JSON report saved to: {json_path}")
    except Exception as e:
        print(f"[✗] Error writing JSON report: {e}")
        logging.error(f"Error writing JSON report: {e}", exc_info=True)
        return

    try:
        with open(csv_path, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["Host", "Port", "Service", "State", "Vulnerabilities"])
            for host, data in scan_results.items():
                for proto, ports in data.get("protocols", {}).items():
                    for port, details in ports.items():
                        writer.writerow([host, port, details["service"], details["state"], ", ".join(vulnerabilities.get(host, []))])
        print(f"[✓] CSV report saved to: {csv_path}")
        logging.info(f"CSV report saved to: {csv_path}")

    except Exception as e:
        print(f"[✗] Error writing CSV report: {e}")
        logging.error(f"Error writing CSV report: {e}", exc_info=True)
        return

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(200, 10, txt="Cybersecurity Scan Report", ln=True, align="C")
    pdf.ln(10)

    for host, data in scan_results.items():
        pdf.set_font("Arial", "B", 12)
        pdf.set_text_color(0, 0, 255)  # Highlight hostname
        pdf.cell(200, 10, txt=f"Host: {host}", ln=True)

        pdf.set_font("Arial", size=11)
        pdf.set_text_color(0, 0, 0)
        #Create data table in PDF
        table_data = [["Port", "Service", "State", "Vulnerabilities"]]
        for proto, ports in data.get("protocols", {}).items():
             for port, details in ports.items():
                 table_data.append([str(port), details['service'], details['state'], ", ".join(vulnerabilities.get(host, []))])


        #Calculate column widths based on content
        col_width = pdf.w / 4.5 #roughly equal, can define per col
        #Output table data
        pdf.set_font('Arial', '', 10)

        for row in table_data:
            for item in row:
                pdf.cell(col_width, 7, str(item), border=1)
            pdf.ln()
        pdf.ln(5) #space

    try:
        pdf.output(pdf_path)
        print(f"[✓] PDF report saved to: {pdf_path}")
        logging.info(f"PDF report saved to: {pdf_path}")

    except Exception as e:
        print(f"[✗] Error writing PDF report: {e}")
        logging.error(f"Error writing PDF report: {e}", exc_info=True)
        return
    print(f"\n[✓] Reports saved to: {report_dir}")

def main():
    """Cybersecurity Automation Workflow"""
    parser = argparse.ArgumentParser(description="Cybersecurity Automation Toolkit")
    parser.add_argument("-n", "--network", help="Network range to scan (e.g., 192.168.1.0/24)")
    parser.add_argument("-a", "--arguments", default="-sS -O --osscan-guess -p 1-1000 -T4 --open -Pn --min-rate 1000 --max-retries 1",
                        help="Custom Nmap arguments (be careful!)")
    parser.add_argument("-o", "--output_dir", help="Directory to save reports")
    parser.add_argument("-f", "--filename", help="Filename for reports (without extension)")

    args = parser.parse_args()

    print("\n=== Cybersecurity Automation Toolkit ===")
    logging.info("Starting Cybersecurity Automation Toolkit")

    # Step 1: Detect Network Subnet
    network_range = args.network if args.network else detect_subnet()

    # Step 2: Find Live Hosts
    live_hosts = find_live_hosts(network_range)
    if not live_hosts:
        print("[✗] No active devices found. Exiting...")
        logging.warning("No active devices found. Exiting...")
        sys.exit(1)  # Exit with a non-zero code

    scan_results = {}

    # Step 3: Manual Input & Nmap Scan Loop
    for host in live_hosts:
        print(f"\n[📌] Processing {host}...")

        # Step 3a: Get Manual Hardware & Software Input
        hardware_info = manual_hardware_and_software_input(host)

        # Step 3b: Perform Nmap Scan
        nmap_data = scan_network(host, args.arguments)  # Using args.arguments
        scan_results[host] = {
            "hardware_info": hardware_info,  # Store manual input
            "nmap_scan": nmap_data  # Store scan results
        }

    # Step 4: Analyze vulnerabilities
    vulnerabilities = analyze_vulnerabilities(scan_results)

    # Step 5: Display results in a tabular format
    display_results(scan_results, vulnerabilities)

    # Step 6: Generate reports
    output_dir = args.output_dir if args.output_dir else get_report_directory()
    filename = args.filename if args.filename else get_report_filename()

    generate_report(scan_results, vulnerabilities, output_dir, filename)

    print("\n[✓] Cybersecurity Assessment Completed Successfully!")
    logging.info("Cybersecurity Assessment Completed Successfully!")

if __name__ == "__main__":
    main()
