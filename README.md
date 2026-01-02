# Port Scanner with Version Detection

A multi-threaded Python port scanner that detects open ports and attempts to identify service versions running on target hosts.

## Features

- **Fast Scanning**: Multi-threaded scanning for improved performance
- **Service Detection**: Automatically identifies services running on open ports
- **Version Detection**: Retrieves version information for HTTP, FTP, and SSH services
- **Customizable Range**: Scan specific port ranges or all ports
- **Colored Output**: Easy-to-read results with color-coded status messages
- **Verbose Mode**: Optional detailed output for debugging and monitoring

## Requirements

- Python 3.x
- colorama library

## Installation

1. Clone this repository:
```bash
git clone https://github.com/mohamed-elrifai/port-scanner.git
cd port-scanner
```

2. Install required dependencies:
```bash
pip install colorama
```

## Usage

### Basic Syntax
```bash
python port_scanner.py <target> [options]
```

### Arguments

- `target` (required): Target host to scan (hostname or IP address)
- `-s, --start_port`: Starting port number (default: 0)
- `-e, --end_port`: Ending port number (default: 65535)
- `-v, --verbose`: Enable verbose output to see all port statuses

### Examples

Scan common ports (1-1024):
```bash
python port_scanner.py scanme.nmap.org -s 1 -e 1024
```

Scan all ports with verbose output:
```bash
python port_scanner.py 192.168.1.1 -v
```

Scan specific port range:
```bash
python port_scanner.py scanme.nmap.org -s 80 -e 443
```

Quick scan of well-known ports:
```bash
python port_scanner.py 10.0.0.1 -s 20 -e 100
```

## Output

The scanner provides color-coded output:
- **Green**: Open ports
- **Red**: Closed ports (verbose mode only)
- **Yellow**: Errors (verbose mode only)
- **Cyan**: Status messages

### Sample Output
```
Scanning ports from 20 to 100 on scanme.nmap.org...
--------------------------------------------------

Scan complete.

Open ports on scanme.nmap.org:
 - Port 22 (ssh) - Version: SSH-2.0-OpenSSH_7.4
 - Port 80 (http) - Version: Server: Apache/2.4.41 (Ubuntu)
```

## Limitations

1. Version detection is only implemented for HTTP (port 80), FTP (port 21), and SSH (port 22)
2. Uses TCP connect scans, which may be detected by firewalls or IDS systems
3. No rate limiting between scans
4. IPv6 addresses are not currently supported
5. Limited error handling for invalid hosts or unreachable networks

## Future Enhancements

- Extended service version detection (SMTP, DNS, etc.)
- Enhanced banner grabbing capabilities
- Export scan results to file (JSON, CSV, XML)
- UDP port scanning support
- Vulnerability database integration
- Stealth scanning options
- IPv6 support
- Rate limiting and scan delay options

## Legal Disclaimer

**IMPORTANT**: This tool is provided for educational purposes and authorized security testing only. Unauthorized port scanning may be illegal in your jurisdiction and violate network policies or terms of service.

- Only scan systems you own or have explicit permission to test
- Unauthorized scanning may result in legal consequences
- Be aware of and comply with local laws and regulations
- Respect network policies and terms of service

The authors assume no liability for misuse of this tool.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.



