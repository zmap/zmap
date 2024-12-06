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
MAX_ERRORS = -1 # Number of errors before early exit, -1 to disable
TOP_LEVEL_DIR = "/Users/phillip/zmap-dev/zmap/"
# TOP_LEVEL_DIR = "/home/pstephens/zmap-dev/zmap/"
BLOCKLIST_FILE = "conf/blocklist.conf"
ZMAP_ABS_PATH = "src/zmap"

WARNING_COLOR = '\033[93m'

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
    bitmap_by_port = {}
    for port in ports:
        bitmap_by_port[port] = bitarray(IPV4_SPACE)
    return bitmap_by_port

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
            if MAX_ERRORS != -1 and len(errors) >= MAX_ERRORS:
                # early exit optimization
                return errors
        difference_bitmap = ~(bitmap[port] | blocked_bitmap) # equiv. to not blocked and not scanned
        for diff_i in difference_bitmap.search(bitarray('1')):  # Find the first unscanned IP
            ip_str = str(IPv4Address(diff_i))
            err_str = f"{ip_str}:{port} was not blocked and not scanned"
            print(err_str)
            errors.append(err_str)
            if MAX_ERRORS != -1 and len(errors) >= MAX_ERRORS:
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
        with self.subTest("Negative Test Case - Scanned IP/Port that is blocked"):
            ip = int(IPv4Address("2.2.2.2"))
            self.bitmap[80].setall(True)
            self.bitmap[81].setall(True)
            self.blocklist_bitmap[ip] = True
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap)
            self.assertGreater(len(errors), 0)
            self.assertIn("2.2.2.2:80 was blocked and scanned", errors)
            self.assertIn("2.2.2.2:81 was blocked and scanned", errors)
        with self.subTest("Negative Test Case - Not-scanned IP/Port that isn't blocked"):
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
        with self.subTest("Postive Test Case"):
            self.bitmap[80].setall(True)
            self.bitmap[81].setall(True)
            self.blocklist_bitmap.setall(False)
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap)
            self.assertEqual(len(errors), 0)


def run_test(scanner_command, ports):
    blocklist = load_blocklist(TOP_LEVEL_DIR + BLOCKLIST_FILE)
    blocklist_bitmap = create_blocklist_bitmap(blocklist)
    print("DEBUG: blocklist loaded and bitmap created")
    bitmap = create_bitmap(ports)
    errors = []

    try:
        process = subprocess.Popen(
            scanner_command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=1024 * 1024 * 6,  # 6MB buffer
        )
        # Process stderr in real time and print it to sys.stdout so we can see ZMap progress in logs
        def stream_stderr(proc_stderr):
            for line in proc_stderr:
                sys.stdout.write(str(line) + "\n")  # Directly forward stderr to stdout in real time

        import threading
        stderr_thread = threading.Thread(target=stream_stderr, args=(process.stderr,))
        stderr_thread.start()

        size_of_struct = 6  # 4 bytes for IP, 2 bytes for port
        format_str = "!IH" # network byte order, unsigned int, unsigned short
        chunk = bytearray(size_of_struct * 256)
        while True:
            chunk = process.stdout.read(size_of_struct * 256)
            if not chunk:
                break  # End of output

            for ip, port in struct.iter_unpack(format_str, chunk):
                if port not in ports:
                    print(f"{WARNING_COLOR}Unexpected port ({port}) with IP ({IPv4Address(ip)})")
                    errors.append(f"Unexpected port ({port}) with IP ({IPv4Address(ip)})")
                    continue
                if bitmap[port][ip]:
                    print(f"{WARNING_COLOR}Error: {IPv4Address(ip)},{port} scanned more than once")
                    errors.append(f"Error: {IPv4Address(ip)},{port} scanned more than once")
                    sys.exit(1)
                bitmap[port][ip] = True

            if MAX_ERRORS != -1 and len(errors) >= MAX_ERRORS:
                break

        process.stdout.close()
        process.wait()
        stderr_thread.join()  # Ensure stderr thread finishes

    except Exception as e:
        print(f"Error during execution: {e} + {e.with_traceback()}")
        return
    print(f"DEBUG: execution completed with {len(errors)} errors, proceeding to bitmap validation")
    for error in validate_bitmap(bitmap, ports, blocklist_bitmap):
        print(f"Bitmap Validation Error: {error}")
        errors.append(error)

    # Final validation/summary
    if len(errors) == 0:
        print("Integration test passed successfully.")
        sys.exit(0)
    else:
        print(f"{len(errors)} Errors encountered during scan:\n")
        for error in errors:
            print(f"During-Scan Error: {error}")
        sys.exit(1)


# def test_multi_port_scan_two_ports():
if __name__ == "__main__":
    scanner_cmd = [
        TOP_LEVEL_DIR + ZMAP_ABS_PATH, "-p", "80,443", "-T", "1",# "--seed", "2",
        "-B", "200G", "--fast-dryrun", "-c", "0", "--batch", "256", "--verbosity", "5", "--blocklist-file", TOP_LEVEL_DIR + BLOCKLIST_FILE
    ]
    print(" ".join(scanner_cmd))
    # Seed = 2,T = 4, -p = 80 with port 80 gives us a more than once scan in 30 seconds, or -n 140308924
    ports_to_scan = [80,443]

    run_test(scanner_cmd, ports_to_scan)
