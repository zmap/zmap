import os
import subprocess
import struct
import socket
import sys
import unittest
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

def validate_bitmap(bitmap, ports, blocked_bitmap:bitarray):
    """Validate that all non-blocklisted IPs are scanned."""
    errors = []
    for port in ports:
        difference_bitmap = bitmap[port] & blocked_bitmap
        for diff_i in difference_bitmap.search(bitarray('1')):  # Find the first unscanned IP
            ip_str = str(IPv4Address(diff_i))
            err_str = f"{ip_str}:{port} was blocked and scanned"
            print(err_str)
            errors.append(err_str)
            if len(errors) >= MAX_ERRORS:
                # early exit optimization
                return errors
        difference_bitmap = ~(bitmap[port] | blocked_bitmap) # equiv. to not blocked and not scanned
        for diff_i in difference_bitmap.search(bitarray('1')):  # Find the first unscanned IP
            ip_str = str(IPv4Address(diff_i))
            err_str = f"{ip_str}:{port} was not blocked and not scanned"
            print(err_str)
            errors.append(err_str)
            if len(errors) >= MAX_ERRORS:
                # early exit optimization
                return errors
    return errors

class TestBitmapValidation(unittest.TestCase):

    def setUp(self):
        self.ports = [80, 81]
        self.bitmap = create_bitmap(self.ports)
        self.blocklist_bitmap = bitarray(IPV4_SPACE)
        self.blocklist_bitmap.setall(False)

    def test_validate_bitmap(self):
        with self.subTest("Scanned IP/Port that is blocked"):
            ip = int(IPv4Address("2.2.2.2"))
            self.bitmap[80].setall(True)
            self.bitmap[81].setall(True)
            self.blocklist_bitmap[ip] = True
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap)
            self.assertGreater(len(errors), 0)
            self.assertIn("2.2.2.2:80 was blocked and scanned", errors)
            self.assertIn("2.2.2.2:81 was blocked and scanned", errors)
        with self.subTest("Not-scanned IP/Port that isn't blocked"):
            self.bitmap[80].setall(True)
            self.bitmap[81].setall(True)
            self.blocklist_bitmap.setall(False)
            ip = int(IPv4Address("3.3.3.3"))
            self.bitmap[80][ip] = False
            self.bitmap[81][ip] = False
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap)
            self.assertGreater(len(errors), 0)
            self.assertIn("3.3.3.3:80 was not blocked and not scanned", errors)
            self.assertIn("3.3.3.3:81 was not blocked and not scanned", errors)


def run_test(scanner_command, ports):
    blocklist = load_blocklist(TOP_LEVEL_DIR + BLOCKLIST_FILE)
    blocklist_bitmap = create_blocklist_bitmap(blocklist)
    print("DEBUG: blocklist loaded and bitmap created")
    bitmap = create_bitmap(ports)
    errors = 0
    # bitmap[80] = ~blocklist_bitmap
    # bitmap[81] = ~blocklist_bitmap
    # blocklist_bitmap[int(IPv4Address("1.1.1.1"))] = True
    # bitmap[80][int(IPv4Address("1.1.1.1"))] = False


    size_of_struct = 6  # 4 bytes for IP, 2 bytes for port
    chunk_size = 1024 * 4 * size_of_struct  # 4k entries

    try:
        process = subprocess.Popen(
            scanner_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=chunk_size * 4,
        )
        # Process stderr in real time and print it to sys.stdout
        def stream_stderr(proc_stderr):
            for line in proc_stderr:
                sys.stdout.write(str(line) + "\n")  # Directly forward stderr to stdout in real time

        import threading
        stderr_thread = threading.Thread(target=stream_stderr, args=(process.stderr,))
        stderr_thread.start()

        while True:
            # Read 6000 bytes/1k entries at a time
            chunk = process.stdout.read(chunk_size)
            if not chunk:
                break  # End of output

            # Efficient iteration using struct.unpack_from
            ip = 0
            port = 0
            for i in range(len(chunk) // size_of_struct):
                ip, port = struct.unpack_from("!IH", chunk, i * size_of_struct)
                if port not in ports:
                    ip_str = socket.inet_ntoa(ip)
                    print(f"Unexpected port ({port}) with IP ({ip_str})")
                    errors += 1
                    continue
                if is_blocklisted(ip, blocklist_bitmap):
                    ip_str = socket.inet_ntoa(ip)
                    print(f"Error: Scanned blocklisted IP {ip_str},{port}")
                    errors += 1
                if bitmap[port][ip]:
                    ip_str = socket.inet_ntoa(ip)
                    print(f"Error: {ip_str},{port} scanned more than once")
                    errors += 1
                bitmap[port][ip] = True

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
    validation_errors = validate_bitmap(bitmap, ports, blocklist_bitmap)
    for error in validation_errors:
        print(f"Validation Error: {error}")
        errors += 1
        if errors >= MAX_ERRORS:
            break

    if errors == 0:
        print("Integration test passed successfully.")
        os._exit(0)
    else:
        print(f"Integration test failed with {errors} errors.")
        os._exit(1)

# def test_multi_port_scan_two_ports():
if __name__ == "__main__":
    scanner_cmd = [
        TOP_LEVEL_DIR + ZMAP_ABS_PATH, "-p", "80-81", "-T", "4", "--cores=0,1,2,3,4,5",
        "-B", "200G", "--fast-dryrun", "-c", "0", "--batch", "256", "--seed", "10", "--blocklist-file", TOP_LEVEL_DIR + BLOCKLIST_FILE
    ]
    ports_to_scan = [80, 81]

    run_test(scanner_cmd, ports_to_scan)
