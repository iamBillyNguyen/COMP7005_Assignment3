import argparse
import ipaddress
import threading
import time

from scapy.all import *
from queue import Queue
from scapy.layers.inet import TCP, IP

IP_ADDRESS = 0
LOWER_BOUND = 1
UPPER_BOUND = 65535
DELAY = 0

OPEN = "SA"     # SYN-ACK
CLOSE = "RA"    # RST-ACK

queue = Queue()

# TODO - Get Delay working, finish docs once done

def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--ip", type=str, required=True, help="IP Address to scan ports on")
    parser.add_argument("-s", "--start", type=int, help="Lower bound of the port range to scan for (Default is 1)")
    parser.add_argument("-e", "--end", type=int, help="Higher bound of the port range to scan for (Default is 65535)")
    parser.add_argument("-d", "--delay", type=int, help="Delay between scans in millisecond (Default is 0)")

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
        LOWER_BOUND = args.start

    if args.end is not None:
        if LOWER_BOUND > args.end > UPPER_BOUND:
            parser.print_help()
            sys.exit("Upper bound must be less than or equal to 65535.")
        UPPER_BOUND = args.end

    if LOWER_BOUND > UPPER_BOUND:
        parser.print_help()
        sys.exit("Lower bound must be less than upper bound.")

    if args.delay is not None:
        if args.delay < 0:
            parser.print_help()
            sys.exit("Delay must be greater than or equal to 0.")
        else:
            DELAY = args.delay

    print("IP Address:\t", IP_ADDRESS)
    print("Start:\t\t", LOWER_BOUND)
    print("End:\t\t", UPPER_BOUND)
    print("Delay:\t\t", DELAY)

def is_valid_ip(address):
    try:
        # Try to create an IP address object from the provided address
        ipaddress.ip_address(address)
        return True
    except ValueError:
        return False

def scan_port(port):
    ip_layer = IP(dst=IP_ADDRESS)

    tcp_layer = TCP(dport=port, flags="S")
    packet = ip_layer / tcp_layer
    response = sr1(packet, timeout=1, verbose=False)
    print(f"Response: {response}")

    if response and response.haslayer(TCP):
        if response[TCP].flags == OPEN:  # SYN-ACK means open
            # open_ports.append(port)
            print(f"Port {port} is open.")
            # Send RST to gracefully close the connection
            sr1(ip_layer / TCP(dport=port, flags="R"), timeout=1, verbose=False)
        elif response[TCP].flags == CLOSE:  # RST-ACK means closed
            print(f"Port {port} is closed.")
        else:
            print(f"Port {port} is filtered or dropped.")

def queue_ports():
    for port in range(LOWER_BOUND, UPPER_BOUND+1):
        queue.put(port)

def dequeue_and_handle_port():
    while not queue.empty():
        port = queue.get()
        scan_port(port)
        queue.task_done()
        time.sleep(DELAY)

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
    handle_scan_with_multi_threading(10)