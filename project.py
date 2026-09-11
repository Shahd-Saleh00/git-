import socket  
import time  
import concurrent.futures  
import argparse


def resolve_host(target): 
    try:
        return socket.gethostbyname(target)  
    except socket.gaierror:  
        return None  


def scan_port(host, port, timeout=1.0):  
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    sock.settimeout(timeout)  
    try:
        result = sock.connect_ex((host, port))  
        if result != 0:
            return (port, False, "")
        banner = ""  
        try:
            sock.settimeout(0.5)  
            banner = sock.recv(1024).decode(errors="ignore").strip()  
        except (socket.timeout, UnicodeDecodeError):  
            pass  
        return (port, True, banner)  
    except (socket.timeout, ConnectionRefusedError, OSError):  
        return (port, False, "")  
    finally:
        sock.close()  


def parse_ports(spec):      
    ports = set()  
    for chunk in spec.split(","):  
        chunk = chunk.strip()  
        if not chunk:  
            continue  
        if "-" in chunk:  
            lo, hi = chunk.split("-", 1)  
            lo, hi = int(lo), int(hi)
            if lo > hi:
                raise ValueError("port ranges must be ascending")
            ports.update(range(lo, hi + 1))
        else:  # a single port like "80"
            ports.add(int(chunk))  
    if not ports or any(port < 1 or port > 65535 for port in ports):
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)  


def scan_host(host, ports, timeout=1.0, workers=100): 
    """Return a list of (port, banner) tuples for every open port on `host`."""
    open_ports = []  
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:  
        futures = {pool.submit(scan_port, host, p, timeout): p for p in ports}  
        for fut in concurrent.futures.as_completed(futures):  
            port, is_open, banner = fut.result()  
            if is_open:  
                open_ports.append((port, banner))  
    return sorted(open_ports)  


def grab_banner(host, port, timeout=1.0):     
    _, is_open, banner = scan_port(host, port, timeout)  
    return banner if is_open else ""  


def timed_scan(host, ports, timeout=1.0):      
    start = time.time()  
    results = scan_host(host, ports, timeout)  
    return results, time.time() - start  


def main():
    parser = argparse.ArgumentParser(description="Scan TCP ports on a host.")
    parser.add_argument("host", help="hostname or IPv4 address to scan")
    parser.add_argument("-p", "--ports", default="1-1024", help="ports, e.g. 22,80,443 or 1-1024")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="connection timeout in seconds")
    parser.add_argument("-w", "--workers", type=int, default=100, help="maximum concurrent connections")
    args = parser.parse_args()

    if args.timeout <= 0 or args.workers < 1:
        parser.error("timeout must be positive and workers must be at least 1")

    host = resolve_host(args.host)
    if host is None:
        parser.error(f"could not resolve host: {args.host}")
    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    results, elapsed = timed_scan(host, ports, args.timeout)
    print(f"Scanning {args.host} ({host}) ports {args.ports}")
    for port, banner in results:
        print(f"OPEN  {port}/tcp" + (f"  {banner}" if banner else ""))
    print(f"Found {len(results)} open port(s) in {elapsed:.2f}s")


if __name__ == "__main__":
    main()



