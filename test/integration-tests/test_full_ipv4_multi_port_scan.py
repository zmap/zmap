import re
import subprocess
import struct
import socket
import sys
from bitarray import bitarray
from ipaddress import IPv4Address, IPv4Network

# Constants
IPV4_SPACE = 2**32  # Total number of IPv4 addresses
MAX_ERRORS = 10
TOP_LEVEL_DIR = "/Users/phillip/zmap-dev/zmap/"
# TOP_LEVEL_DIR = "/home/pstephens/zmap-dev/zmap/"
BLOCKLIST_FILE = "conf/blocklist.conf"
ZMAP_ABS_PATH = "src/zmap"

BLOCKLISTED = -1
DUPLICATE = -2
SUCCESS = 1


def load_blocklist(file_path):
    """Load blocklist CIDR ranges from a file."""
    blocklist = []
    try:
        with open(file_path, "r") as file:
            for line in file:
                # Ignore comments and empty lines
                line = line.split("#")[0].strip()
                if line:
                    blocklist.append(IPv4Network(line))
    except Exception as e:
        print(f"Error loading blocklist: {e}")
    return blocklist

def is_blocklisted(ip:int, blocklist_bitmap):
    """Check if an IP address is in the blocklist."""
    return blocklist_bitmap[ip]

def create_bitmap(ports):
    """Create a bitmap for all IPs and each port."""
    return {port: bitarray(IPV4_SPACE) for port in ports}

def create_blocklist_bitmap(blocklist):
    """Create a bitmap for all blocklisted IPs."""
    bitmap = bitarray(IPV4_SPACE)
    for net in blocklist:
        number_ips = net.num_addresses
        start_ip = int(net.network_address)
        bitmap[start_ip:start_ip + number_ips] = True # efficient bulk set
        print(f"DEBUG: blocklist net: {net} with size {net.num_addresses}")
    return bitmap

def track_pair(bitmap, ip:int, port, blocklist_bitmap):
    """Mark an IP/port as scanned, unless it's blocklisted."""
    if is_blocklisted(ip, blocklist_bitmap):
        return BLOCKLISTED
    if bitmap[port][ip]:
        return DUPLICATE
    bitmap[port][ip] = True
    return SUCCESS

def validate_bitmap(bitmap, ports, blocklist):
    """Validate that all non-blocklisted IPs are scanned."""
    errors = []
    for port in ports:
        for i in range(IPV4_SPACE):
            if not bitmap[port][i]:
                ip = IPv4Address(i)
                if not is_blocklisted(ip, blocklist):
                    errors.append(f"{ip},{port} was not scanned.")
                    if len(errors) >= MAX_ERRORS:
                        return errors
    return errors

def run_test(scanner_command, ports):
    blocklist = load_blocklist(TOP_LEVEL_DIR + BLOCKLIST_FILE)
    blocklist_bitmap = create_blocklist_bitmap(blocklist)
    print("DEBUG: blocklist loaded and bitmap created")
    bitmap = create_bitmap(ports)
    errors = 0
    try:
        process = subprocess.Popen(
            scanner_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        # Process stderr in real time and print it to sys.stdout
        def stream_stderr(proc_stderr):
            for line in proc_stderr:
                sys.stdout.write(str(line) + "\n")  # Directly forward stderr to stdout in real time

        import threading
        stderr_thread = threading.Thread(target=stream_stderr, args=(process.stderr,))
        stderr_thread.start()

        while True:
            # Read 6 bytes at a time
            chunk = process.stdout.read(6)
            if not chunk:
                break  # End of output

            if len(chunk) < 6:
                continue  # Skip incomplete data chunks

            # Unpack the 6-byte chunk (4 bytes for IP, 2 bytes for port)
            ip, port = struct.unpack('!4sH', chunk)

            ip_as_int = int.from_bytes(ip)
            if port not in ports:
                ip_str = socket.inet_ntoa(ip)
                print(f"Unexpected port ({port}) with IP ({ip_str})")
                errors += 1
                continue
            result = track_pair(bitmap, ip_as_int, port, blocklist_bitmap)
            if result == BLOCKLISTED:
                ip_str = socket.inet_ntoa(ip)
                print(f"Error: Scanned blocklisted IP {ip_str},{port}")
                errors += 1
            elif result == DUPLICATE:
                ip_str = socket.inet_ntoa(ip)
                print(f"Error: {ip_str},{port} scanned more than once")
                errors += 1

            if errors >= MAX_ERRORS:
                break

        process.stdout.close()
        process.wait()
        stderr_thread.join()  # Ensure stderr thread finishes

    except Exception as e:

        print(f"Error during execution: {e}")
        return
    print(f"DEBUG: execution completed with {errors} errors, proceeding to bitmap validation")

    # Final validation
    validation_errors = validate_bitmap(bitmap, ports, blocklist)
    for error in validation_errors:
        print(f"Validation Error: {error}")
        errors += 1
        if errors >= MAX_ERRORS:
            break

    if errors == 0:
        print("Integration test passed successfully.")
    else:
        print(f"Integration test failed with {errors} errors.")

# def test_multi_port_scan_two_ports():
if __name__ == "__main__":
    scanner_cmd = [
        TOP_LEVEL_DIR + ZMAP_ABS_PATH, "-p", "80-81", "-T", "1", "--cores=0,1,2",
        "-B", "200G", "--fast-dryrun", "-c", "1", "--seed", "10", "--blocklist-file", TOP_LEVEL_DIR + BLOCKLIST_FILE
    ]
    ports_to_scan = [80, 81]

    run_test(scanner_cmd, ports_to_scan)
