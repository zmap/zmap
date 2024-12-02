import re
import subprocess
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

def is_blocklisted(ip, blocklist):
    """Check if an IP address is in the blocklist."""
    ip_addr = IPv4Address(ip)
    return any(ip_addr in net for net in blocklist)

def create_bitmap(ports):
    """Create a bitmap for all IPs and each port."""
    return {port: bitarray(IPV4_SPACE) for port in ports}

def track_pair(bitmap, ip, port, blocklist):
    """Mark an IP/port as scanned, unless it's blocklisted."""
    if is_blocklisted(ip, blocklist):
        return "blocklisted"
    ip_index = int(IPv4Address(ip))
    if bitmap[port][ip_index]:
        return "duplicate"
    bitmap[port][ip_index] = True
    return "success"

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
    bitmap = create_bitmap(ports)
    errors = 0

    # Regex to parse output
    ip_regex = re.compile(r"^ip.*\bdaddr:\s([\d\.]+)")
    tcp_regex = re.compile(r"^tcp.*\bdest:\s(\d+)")

    try:
        process = subprocess.Popen(
            scanner_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=-1
        )
        # Process stderr in real time and print it to sys.stdout
        def stream_stderr(proc_stderr):
            for line in proc_stderr:
                sys.stdout.write(line)  # Directly forward stderr to stdout in real time

        import threading
        stderr_thread = threading.Thread(target=stream_stderr, args=(process.stderr,))
        stderr_thread.start()

        current_dst_port = None
        current_dst_ip = None
        for line in process.stdout:
            tcp_match = tcp_regex.match(line)
            if tcp_match:
                current_dst_port = int(tcp_match.group(1))
                continue
            ip_match = ip_regex.match(line)
            if ip_match:
                current_dst_ip = ip_match.group(1)

            if current_dst_port and current_dst_ip:
                if current_dst_port in ports:
                    result = track_pair(bitmap, current_dst_ip, current_dst_port, blocklist)
                    if result == "blocklisted":
                        print(f"Error: Scanned blocklisted IP {current_dst_ip},{current_dst_port}")
                        errors += 1
                    elif result == "duplicate":
                        print(f"Error: {current_dst_ip},{current_dst_port} scanned more than once")
                        errors += 1
                else:
                    print(f"Unexpected port ({current_dst_port}) with IP ({current_dst_ip})")
                    errors += 1
                # Reset
                current_dst_ip = None
                current_dst_port = None

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
        "-B", "200G", "--dryrun", "-c", "1", "--blocklist-file", TOP_LEVEL_DIR + BLOCKLIST_FILE
    ]
    ports_to_scan = [80, 81]

    run_test(scanner_cmd, ports_to_scan)
