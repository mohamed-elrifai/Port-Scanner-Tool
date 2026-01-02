import socket
import threading
import argparse
from colorama import Fore, init

""" Limitations:
1. Version detection is only implemented for HTTP (port 80), FTP (port 21), and SSH (port 22). Other services will not have version info.
2. The scanner uses TCP connect scans, which may be detected by firewalls or intrusion detection systems.
3. The script does not handle rate limiting or delays between scans, which may lead to inaccurate results on some networks.
4. The script does not currently support IPv6 addresses.
5. The script does not include error handling for invalid target hosts or unreachable networks.
"""
""" Future Enhancements:
1. Add more service version detection for additional common ports (e.g., SMTP, DNS).
2. Implement banner grabbing for more services.
3. Add an option to save scan results to a file.
4. Include an option for UDP port scanning.
5. Integrate with a database of known vulnerabilities for detected services.
6. Stealth scanning options to avoid detection by firewalls/IDS.
"""

# Initialize colorama
init(autoreset=True)

# List to store open ports and their versions as dictionaries
open_ports_with_versions = []

# Function to map port numbers to service names
def get_service_name(port):
    try:
        # Try to get the service name using socket.getservbyport()
        service_name = socket.getservbyport(port)
        return service_name
    except OSError:
        # If no service name is found, return the port number
        return str(port)

# Function to get version info from HTTP server (port 80)
def get_http_version(target, port):
    try:
        # Send an HTTP GET request to the server
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, port))
        s.send(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
        response = s.recv(1024).decode()
        s.close()
        
        # Look for "Server" header to extract version
        for line in response.split("\r\n"):
            if line.lower().startswith("server:"):
                return line
    except Exception:
        pass
    return "Unknown HTTP version"

# Function to get FTP version (port 21)
def get_ftp_version(target, port):
    try:
        # Send an FTP command to get the server version
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, port))
        banner = s.recv(1024).decode()
        s.close()

        # The banner often includes the version info at the start
        return banner.splitlines()[0]
    except Exception:
        pass
    return "Unknown FTP version"

# Function to get SSH version (port 22)
def get_ssh_version(target, port):
    try:
        # Connect to the SSH port and receive the banner
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        s.connect((target, port))
        banner = s.recv(1024).decode()
        s.close()

        # SSH servers usually return a banner containing the version
        return banner.splitlines()[0]
    except Exception:
        pass
    return "Unknown SSH version"

# Function to scan a single port and attempt version detection
def scan_port(target, port, verbose):
    try:
        # Create a socket object
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        # Try to connect to the target and port
        result = s.connect_ex((target, port))

        # If result is 0, it means the port is open
        if result == 0:
            service_name = get_service_name(port)

            # Attempt to get version info for certain services
            version_info = "No version info"
            if port == 80:
                version_info = get_http_version(target, port)
            elif port == 21:
                version_info = get_ftp_version(target, port)
            elif port == 22:
                version_info = get_ssh_version(target, port)

            # Store open ports and their version info in the global list as dictionaries
            open_ports_with_versions.append({
                "port": port,
                "service": service_name,
                "version": version_info
            })

            if verbose:
                print(f"{Fore.GREEN}[OPEN] Port {port} ({service_name}) on {target} is open. Version: {version_info}")
        else:
            if verbose:
                print(f"{Fore.RED}[CLOSED] Port {port} on {target} is closed.")

        # Close the socket
        s.close()

    except socket.error as err:
        if verbose:
            print(f"{Fore.YELLOW}[ERROR] Error scanning port {port} on {target}: {err}")

# Function to scan multiple ports concurrently using threading
def scan_ports(target, start_port, end_port, verbose=False):
    global open_ports_with_versions
    open_ports_with_versions.clear()  # Clear the list before starting the scan

    print(f"\n{Fore.CYAN}Scanning ports from {start_port} to {end_port} on {target}...\n")
    print(f"{Fore.WHITE}{'-'*50}\n")

    # List to hold all threads
    threads = []

    for port in range(start_port, end_port + 1):
        # Create a new thread for each port scan
        thread = threading.Thread(target=scan_port, args=(target, port, verbose))

        # Start the thread
        thread.start()

        # Add the thread to the list of threads
        threads.append(thread)

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    # After all threads are done, print the open ports and their services
    print(f"\n{Fore.GREEN}Scan complete.\n")
    print(f"{Fore.CYAN}Open ports on {target}:")
    if open_ports_with_versions:
        for port_info in open_ports_with_versions:
            print(f"{Fore.GREEN} - Port {port_info['port']} ({port_info['service']}) - Version: {port_info['version']}")
    else:
        print(f"{Fore.RED}No open ports found.")

# Parse command line arguments using argparse
def parse_args():
    parser = argparse.ArgumentParser(description="Port Scanner with version detection.")
    parser.add_argument("target", help="Target host to scan (e.g., scanme.nmap.org)")
    parser.add_argument("-s", "--start_port", type=int, default=0, help="Start port number (default: 0)")
    parser.add_argument("-e", "--end_port", type=int, default=65535, help="End port number (default: 65535)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    return parser.parse_args()

# Main function to execute the port scanning
if __name__ == "__main__":
    # Parse arguments
    args = parse_args()
    
    # Run the scan with the provided arguments
    scan_ports(args.target, args.start_port, args.end_port, verbose=args.verbose)
