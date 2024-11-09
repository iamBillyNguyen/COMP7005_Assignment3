import argparse
import ipaddress
import threading
import time

from scapy.all import *
from queue import Queue
from scapy.layers.inet import TCP, IP

LOWER_BOUND = 1
UPPER_BOUND = 65535
OPEN = "SA"     # SYN-ACK
CLOSE = "RA"    # RST-ACK

IP_ADDRESS = "0"
START_PORT = LOWER_BOUND
END_PORT = UPPER_BOUND
DELAY = 0

queue = Queue()

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, required=True, help="IP Address to scan ports on")
    parser.add_argument("-s", "--start", type=int, help="Lower bound of the port range to scan for (Default is 1)")
    parser.add_argument("-e", "--end", type=int, help="Higher bound of the port range to scan for (Default is 65535)")
    parser.add_argument("-d", "--delay", type=int, help="Delay between scans in second (Default is 0)")

    try:
        args = parser.parse_args()

    except SystemExit as e:
        parser.print_help()
        sys.exit(e.code)

    handle_arguments(args, parser)

def handle_arguments(args, parser):
    global IP_ADDRESS, LOWER_BOUND, UPPER_BOUND, DELAY

    if is_valid_ip(args.ip):
        IP_ADDRESS = args.ip
    else:
        parser.print_help()
        sys.exit("IP Address is not valid")

    if args.start is not None:
        if LOWER_BOUND > args.start > UPPER_BOUND:
            parser.print_help()
            sys.exit("Lower bound must be greater than or equal to 1.")
        START_PORT = args.start

    if args.end is not None:
        if LOWER_BOUND > args.end > UPPER_BOUND:
            parser.print_help()
            sys.exit("Upper bound must be less than or equal to 65535.")
        END_PORT = args.end

    if START_PORT > END_PORT:
        parser.print_help()
        sys.exit("Lower bound must be less than upper bound.")

    if args.delay is not None:
        if args.delay < 0:
            parser.print_help()
            sys.exit("Delay must be greater than or equal to 0.")
        else:
            DELAY = args.delay

    print("IP Address:\t", IP_ADDRESS)
    print("Start:\t\t", START_PORT)
    print("End:\t\t", END_PORT)
    print("Delay:\t\t", DELAY)

def is_valid_ip(address):
    try:
        # Try to create an IP address object from the provided address
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def scan_port(port):
    print(f"Scanning port {port}")
    ip_layer = IP(dst=IP_ADDRESS)

    tcp_layer = TCP(dport=port, flags="S")
    packet = ip_layer / tcp_layer
    response = sr1(packet, timeout=1, verbose=False)

    # If unable to scan port, send error message and return immediately
    if response is None:
        print(f"Unable to scan port {port}, please check if IP address is reachable.")
        return None

    # Else handle port
    if response.haslayer(TCP):
        if response[TCP].flags == OPEN:  # SYN-ACK means open
            # open_ports.append(port)
            print(f"Port {port} is open.")
            # Send RST to gracefully close the connection
            sr1(ip_layer / TCP(dport=port, flags="R"), timeout=1, verbose=False)
        elif response[TCP].flags == CLOSE:  # RST-ACK means closed
            print(f"Port {port} is closed.")
        else:
            print(f"Port {port} is filtered or dropped.")
    # Bonus feature: delay between each scan
    time.sleep(DELAY)

def queue_ports():
    for port in range(START_PORT, END_PORT+1):
        queue.put(port)

def dequeue_and_handle_port():
    while not queue.empty():
        port = queue.get()
        scan_port(port)
        queue.task_done()

def handle_scan_with_multi_threading(num_threads):
    threads = []

    for _ in range(num_threads):
        t = threading.Thread(target=dequeue_and_handle_port)
        t.start()
        threads.append(t)

    # Wait for all threads to finish
    queue.join()

if __name__ == "__main__":
    parse_arguments()
    queue_ports()

    # Use multi-threading if there is no delay
    thread_num = 3
    # else use 1 thread to scan synchronously with a delay in-between
    if DELAY > 0:
        thread_num = 1

    handle_scan_with_multi_threading(thread_num)
