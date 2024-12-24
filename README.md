# Port Scan Tool

A fast and efficient Go-based port scanner tool for scanning open ports on domains and IP addresses. It supports concurrent scanning and customizable port ranges.

## Features
- Scans multiple domains and IPs simultaneously.
- Configurable port range (default: 1-65535).
- Concurrent workers will speed up the scan (default: 500 workers).
- Option to output results to a file.

## Installation
Prerequisites:

    Go (version 1.16 or higher) is required to install and use this tool.
    
1. Clone this repository:
   ```bash
   git clone https://github.com/sourabhtomar/Portscanner.git
2. cd Portscanner

3. go build -o portscanner main.go


4. mv portscanner /usr/local/bin
## Usage

Command-Line Arguments:
portscan -d <domain or IP> -p <port-range> -o <output-file>

Available Options:

    -d <domain or IP>: Specify a domain or an IP address to scan.
        Example: -d google.com

    -l <file-path>: Provide a file containing a list of domains or IPs (one per line) to scan.
        Example: -l domains.txt

    -p <port-range>: Specify the port range to scan. The default is 1-65535.
        Example: -p 80-1000 to scan ports from 80 to 1000.

    -o <output-file>: Specify a file where the results will be saved.
        Example: -o results.txt
