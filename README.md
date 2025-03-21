# Cybersecurity Automation Toolkit

This is a Python-based cybersecurity automation toolkit designed to perform network scanning, host information gathering, vulnerability analysis, and report generation. It combines manual input with automated Nmap scans to provide a comprehensive overview of network security.

## Features

*   **Network Scanning:** Uses Nmap to scan network ranges and identify live hosts and open ports.
*   **Host Information Gathering:** Gathers hardware and software information via manual input for each host.
*   **Vulnerability Analysis:** Analyzes scan results to identify potential vulnerabilities based on open ports and services (expandable with CVE database integration).
*   **Report Generation:** Generates reports in JSON, CSV, and PDF formats, providing detailed scan results and identified vulnerabilities.
*   **Input Sanitization:** Sanitizes user input to prevent basic injection attacks.
*   **Dynamic Subnet Detection:** Automatically detects the network subnet to simplify configuration.
*   **Custom Nmap Arguments:** Allows users to specify custom Nmap arguments for flexible scanning.
*   **Logging:** Logs errors and important events to a file for easier debugging.
*   **Command-Line Interface:** Provides a command-line interface with options to customize scan parameters and output.

## Dependencies

*   Python 3.6+
*   `python-nmap`
*   `fpdf`
*   `tabulate`
*   `requests`

Install the dependencies using:

```bash
pip install -r requirements.txt
Markdown
(Contents of requirements.txt are:

certifi==2024.2.2
charset-normalizer==3.3.2
fpdf==1.7.2
idna==3.6
nmap==0.0.1
python-nmap==0.7.1
requests==2.31.0
tabulate==0.9.0
urllib3==2.2.0
)

Usage
python cyber_scan.py [options]
Bash
Options
-n, --network: Network range to scan (e.g., 192.168.1.0/24). If not specified, the script will attempt to detect the subnet automatically.

-a, --arguments: Custom Nmap arguments (e.g., -sV -p 22,80,443). Use with caution. Default: -sS -O --osscan-guess -p 1-1000 -T4 --open -Pn --min-rate 1000 --max-retries 1.

-o, --output_dir: Directory to save the reports. If not specified, the script will prompt you to select a directory.

-f, --filename: Filename for the reports (without extension). If not specified, the script will prompt you to enter a filename.

Examples
# Scan a network using the default arguments
python cyber_scan.py -n 192.168.1.0/24

# Scan a network using custom Nmap arguments
python cyber_scan.py -n 192.168.1.0/24 -a "-sV -p 22,80,443"

# Specify the output directory and filename
python cyber_scan.py -n 192.168.1.0/24 -o /path/to/reports -f my_scan
Bash
Workflow
The script detects the network subnet (or uses the user-provided value).

It finds live hosts within the network range using a fast Nmap scan.

For each live host:

It prompts the user to manually input hardware and software details.

It performs an Nmap scan using the specified arguments (or default arguments).

It stores the hardware/software information and scan results.

It analyzes the scan results and identifies potential vulnerabilities.

It displays the scan results and vulnerabilities in a tabular format.

It generates reports in JSON, CSV, and PDF formats and saves them to the specified directory.

Vulnerability Analysis
The analyze_vulnerabilities function currently provides a basic example of vulnerability analysis based on identified services and open ports. For more advanced analysis, you can integrate with a vulnerability database or scanner (e.g., using the vulners library or integrating with commercial tools) to correlate service versions with known vulnerabilities. Remember to do the data population yourself - that will take most of your time.

Logging
The script logs errors and important events to a file named scan.log in the current directory.

Ethical Considerations
Ensure you have explicit permission before scanning any network. Unauthorized network scanning is illegal and unethical.

Use the tool responsibly and avoid causing disruption to network services.

Disclaimer
This tool is provided for educational and informational purposes only. The user assumes all responsibility for its use. The author is not responsible for any damage caused by the use or misuse of this tool.

This README file provides a comprehensive overview of the tool, including its features, dependencies, usage instructions, workflow, vulnerability analysis approach, logging details, and ethical considerations. It should help users understand and use the tool effectively. You can expand this README further to include more detailed explanations or specific examples based on your use case.