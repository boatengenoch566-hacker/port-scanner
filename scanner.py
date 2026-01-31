import argparse
import socket
import sys
from scapy.all import IP, UDP, TCP, ICMP, sr1
import concurrent.futures
import colorama
import json


class Theme:
    """A simple class to manage terminal colors."""
    HEADER = colorama.Fore.CYAN + colorama.Style.BRIGHT
    SUCCESS = colorama.Fore.GREEN
    WARNING = colorama.Fore.YELLOW + colorama.Style.BRIGHT
    INFO = colorama.Fore.WHITE
    RESET = colorama.Style.RESET_ALL


# Initialize once
colorama.init(autoreset=True)


COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389]


def get_args():
    parser = argparse.ArgumentParser(description="Port Scanner Tool")
    parser.add_argument("target", metavar="", help="Enter target IP")

    parser.add_argument(
        "-p", "--ports", metavar="", help="Port range (e.g., '21-80') or a single port (e.g., '443'). Default is common hacker ports.")

    parser.add_argument(
        "-s", "--scan", choices=['connect', 'syn', 'udp'], default='connect', metavar="", help="Type of scan to perform: 'connect' (TCP), 'syn' (Stealth), or 'udp'  Default is 'connect'.")

    parser.add_argument(
        "-o", "--output", metavar="", help="Save results to a JSON file (e.g., 'results.json'). If not specified, saves to the target_address/ip.json .")

    return parser.parse_args()


def parse_ports(port_str):
    """Parse port range string like '80,443,22' or '1-1000'."""
    ports = set()

    if port_str:
        for part in port_str.split(','):
            try:
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    ports.update(range(start, end + 1))
                else:
                    ports.add(int(part))

            except ValueError:
                print(
                    f"{Theme.WARNING}Invalid fomart. port range string should look like '80,443,22' or '1-1000' ")
                sys.exit()

        return sorted(ports)
    else:
        return COMMON_PORTS


def tcp_connect_scan(ip, port):
    try:
        # Creating a socket and the time it should wait for a response
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)

        # Attempt the handshake and close
        result = s.connect_ex((ip, port))
        s.close()

        if result == 0:
            return port
        return None

    except Exception:
        return None


def syn_scan(ip, port):
    try:
        # Creating and sending SYN Packet after it stores it in the response variable.
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        response = sr1(packet, timeout=1, verbose=0)

        # Checking the response
        if response is not None and response.haslayer(TCP):
            if response.getlayer(TCP).flags == 0x12:
                # Send a Reset Packet to close the half-open connection politely
                sr1(IP(dst=ip)/TCP(dport=port, flags="R"), timeout=1, verbose=0)
                return True
        return False
    except Exception:
        return False


def udp_scan(ip, port):
    try:
        # Creating a UDP packet, sending a request and waiting for a response
        packet = IP(dst=ip)/UDP(dport=port)
        response = sr1(packet, timeout=2, verbose=0)

        # Analyzing response
        if response is None:
            return True
        elif response.haslayer(UDP):
            return True
        elif response.haslayer(ICMP):
            # If we get an ICMP type 3 code 3, it's definitely closed
            if int(response.getlayer(ICMP).type) == 3 and int(response.getlayer(ICMP).code) == 3:
                return False
        else:
            return False
    except Exception:
        return False


def perform_scan(ip, port, scan_type):
    if scan_type == "syn":
        return syn_scan(ip, port)
    elif scan_type == "udp":
        return udp_scan(ip, port)
    else:
        return tcp_connect_scan(ip, port)


def get_banner(ip, port):
    try:
        # Send a generic request to wake up the service
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        s.send(b"HEAD / HTTP/1.0\r\n\r\n")
        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner if banner else "Handshake successful, but no banner sent."
    except:
        return f"{Theme.INFO}Could not retrieve banner."


def thread_worker(ip, port, scan_type):
    # Base structure of our result
    result = {
        "port": port,
        "service_info": {},
        "network_info": {}
    }

    if scan_type == 'connect':
        if tcp_connect_scan(ip, port):
            result["service_info"]["banner"] = get_banner(ip, port)
            print(f" {Theme.SUCCESS}\n[+] Port {port}: OPEN (Banner Grabbed)")
            return result

    elif scan_type == 'syn':
        # Using Scapy to peek at the packet
        packet = IP(dst=ip)/TCP(dport=port, flags="S")
        resp = sr1(packet, timeout=1, verbose=0)
        if resp and resp.haslayer(TCP) and resp.getlayer(TCP).flags == 0x12:
            result["network_info"]["ttl"] = resp.ttl
            result["network_info"]["window_size"] = resp.getlayer(TCP).window
            result["network_info"]["flags"] = "SYN-ACK"
            print(
                f" {Theme.SUCCESS}\n[+] Port {port}: OPEN (Stealth Analysis Complete)")
            return result

    elif scan_type == 'udp':
        # UDP is trickier, as we discussed
        packet = IP(dst=ip)/UDP(dport=port)
        resp = sr1(packet, timeout=2, verbose=0)
        if resp is None:  # Open/Filtered
            result["service_info"]["status"] = "Open | Filtered"
            return result
        elif resp.haslayer(ICMP):
            # Capture the detailed ICMP error
            result["service_info"][
                "error_msg"] = f"Type {resp.getlayer(ICMP).type}, Code {resp.getlayer(ICMP).code}"
            return None  # We don't save closed ports usually, but you can if you want!

    return None


if __name__ == "__main__":
    args = get_args()
    try:
        target_ip = socket.gethostbyname(args.target)
        if target_ip:
            print(f"{Theme.HEADER}[+] Scanning Target: {target_ip}")
    except socket.gaierror:
        print(f"{Theme.WARNING}[-] Invalid target!")
        sys.exit()

    port_list = parse_ports(args.ports)

    print(f"{Theme.HEADER}[+] Scan type: {args.scan.upper()}")
    print(f"{Theme.HEADER}[+] Threads: 50")
    print("-" * 40)

    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(
            thread_worker, target_ip, p, args.scan) for p in port_list]

        # The line below ensures that script wait until all threads are finished
        concurrent.futures.wait(futures)

    print("-" * 40)
    print(f"{Theme.SUCCESS}[+] Scan Complete")

    scan_results = []
    for f in futures:
        res = f.result()
        if res:  # Only add if the port was open/interesting
            scan_results.append(res)

    if args.output:
        filename = args.output
        if not filename.endwith('.json'):
            filename += ".json"
    else:
        filename = f"{args.target}.json"

    try:
        with open(filename, "w") as jfile:
            json.dump(scan_results, jfile, indent=4)
        print(f"{Theme.SUCCESS}[+] Detailed report saved to {filename}")
    except Exception as e:
        print(f"{Theme.WARNING}[!] Error saving report: {e}")
