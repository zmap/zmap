from bitarray import bitarray
from ipaddress import IPv4Address, IPv4Network
import os
import struct
import subprocess
import sys
import unittest

IPV4_SPACE = 2**32  # Total number of IPv4 addresses
MAX_ERRORS = 10 # Number of errors before early exit, -1 to disable
TOP_LEVEL_DIR = "../../"
# TOP_LEVEL_DIR = "/Users/phillip/zmap-dev/zmap/" # Uncomment and set if running locally
BLOCKLIST_FILE = "conf/blocklist.conf"
ZMAP_ABS_PATH = "src/zmap"

WARNING_COLOR = '\033[93m'

BLOCKLISTED = -1
DUPLICATE = -2
SUCCESS = 1


def load_blocklist(file_path):
    """
    Load blocklist CIDR ranges from a file.
    
    Args:
        file_path (str): Path to the blocklist file.
    Returns:
        blocklist: List of IPv4Network objects representing the blocklist ranges.
    """
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
    """
    Check if an IP address is in the blocklist

    Args:
        ip (int): IP address to check
        blocklist_bitmap (bitarray): Bitmap of blocklisted IPs 1 = blocklisted, 0 = not blocklisted
    Returns:
        bool: True if the IP is blocklisted, False otherwise
        
    """
    return blocklist_bitmap[ip]

def create_bitmap(ports):
    """Create a bitmap for all IPs and each port
    Args:
        ports (list[int]): List of ports to create bitmaps for
    Returns:
        dict: Dictionary of bitmaps, keyed by port
    """
    bitmap_by_port = {}
    for port in ports:
        bitmap_by_port[port] = bitarray(IPV4_SPACE)
    return bitmap_by_port

def create_blocklist_bitmap(blocklist):
    """Create a bitmap for all blocklisted IPs
    Args:
        blocklist (list[IPv4Network]): List of blocklisted networks
    Returns:
        bitarray: Bitmap of blocklisted IPs 1 = blocklisted, 0 = not blocklisted
    """
    bitmap = bitarray(IPV4_SPACE)
    for net in blocklist:
        number_ips = net.num_addresses
        start_ip = int(net.network_address)
        bitmap[start_ip:start_ip + number_ips] = True # efficient bulk set
        # print(f"DEBUG: blocklist net: {net} with size {net.num_addresses}")
    return bitmap

def validate_bitmap(bitmap, ports, blocked_bitmap:bitarray, subnet:str=None):
    """Validate that all non-blocklisted IPs are scanned
    Args:
        bitmap (dict[int]bitarray): Dictionary of bitarrays, keyed by port
        ports (list[int]): List of ports to validate
        blocked_bitmap (bitarray): Bitmap of blocklisted IPs 1 = blocklisted, 0 = not blocklisted
        subnet (str): Optional subnet to validate against. Used if we only scan a subset of the IPv4 space
    
    Returns:
        list[str]: List of errors encountered during validation, capped at MAX_ERRORS
    """
    expected_ips = ~blocked_bitmap
    if subnet:
        # a subset of the IPv4 space was scanned, so we need to adjust the expected IPs
        subnet = IPv4Network(subnet)
        start_ip = int(subnet.network_address)
        number_ips = subnet.num_addresses
        expected_ips[0:start_ip] = False
        expected_ips[start_ip + number_ips:len(expected_ips)] = False
    errors = []
    for port in ports:
        difference_bitmap = bitmap[port] & ~expected_ips
        for diff_i in difference_bitmap.search(bitarray('1')):  # Find the first unexpected + scanned IP
            ip_str = str(IPv4Address(diff_i))
            err_str = f"{ip_str}:{port} was blocked and scanned"
            print(err_str)
            errors.append(err_str)
            if MAX_ERRORS != -1 and len(errors) >= MAX_ERRORS:
                # early exit optimization
                return errors
        difference_bitmap = ~(bitmap[port] | ~expected_ips) # equiv. to expected and not scanned
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
    """
    Unit tests for validate_bitmap function
    """
    def setUp(self, ports=None):
        if ports is None:
            self.ports = [80, 81]
        else:
            self.ports = ports
        self.bitmap = create_bitmap(self.ports)
        self.blocklist_bitmap = bitarray(IPV4_SPACE)
        self.blocklist_bitmap.setall(False)

    def test_validate_bitmap(self):
        with self.subTest("Negative Test Case - Scanned IP/Port out of subnet"):
            self.setUp([80])
            ip = int(IPv4Address("2.2.2.2"))
            self.bitmap[80].setall(False)
            self.bitmap[80][ip] = True
            self.bitmap[80][ip + 1] = True # out of subnet
            self.bitmap[80][ip - 1] = True # out of subnet
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap, "2.2.2.2/32")
            self.assertEqual(len(errors), 2)
        with self.subTest("Negative Test Case - Didn't scan subnet"):
            self.setUp([80])
            ip = int(IPv4Address("2.2.2.2"))
            self.bitmap[80].setall(False)
            self.bitmap[80][ip - 1] = True # out of subnet
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap, "2.2.2.2/32")
            self.assertEqual(len(errors), 2)
        with self.subTest("Negative Test Case - Scanned IP/Port that is blocked"):
            self.setUp()
            ip = int(IPv4Address("2.2.2.2"))
            self.bitmap[80].setall(True)
            self.bitmap[81].setall(True)
            self.blocklist_bitmap[ip] = True
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap)
            self.assertGreater(len(errors), 0)
            self.assertIn("2.2.2.2:80 was blocked and scanned", errors)
            self.assertIn("2.2.2.2:81 was blocked and scanned", errors)
        with self.subTest("Negative Test Case - Not-scanned IP/Port that isn't blocked"):
            self.setUp()
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
            self.setUp()
            self.bitmap[80].setall(True)
            self.bitmap[81].setall(True)
            self.blocklist_bitmap.setall(False)
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap)
            self.assertEqual(len(errors), 0)
        with self.subTest("Postive Test Case - Subnet"):
            ip = int(IPv4Address("4.4.4.4"))
            self.setUp([80])
            self.blocklist_bitmap.setall(False)
            self.bitmap[80][ip] = True
            errors = validate_bitmap(self.bitmap, self.ports, self.blocklist_bitmap, "4.4.4.4/32")
            self.assertEqual(len(errors), 0)


def run_test(scanner_command, ports, subnet=None):
    """
    Runs an integration test for ZMap, using the provided scanner command and ports to scan.

    Starts a sub-process to run ZMap, pipes it's stderr to the test's stdout so we can see progress in logs.
    Reads stdout of ZMap to get the scanned IPs and ports and uses a per-port bitmap of the IPv4 address space
    to validate that each IP is scanned and scanned exactly once.
    Args:
        scanner_command (list[str]): ZMap scanner command to run
        ports (list[int]): List of ports to scan
        subnet (str): Optional subnet to scan ex. 1.1.1.0/24

    """
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
    except Exception as e:
        print(f"Error during starting ZMap. You may need to set your top-level directory to the correct path: {e}")
        return
    try:
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
                    os._exit(1)
                bitmap[port][ip] = True

            if MAX_ERRORS != -1 and len(errors) >= MAX_ERRORS:
                break

        process.stdout.close()
        process.wait()
        stderr_thread.join()  # Ensure stderr thread finishes

    except Exception as e:
        print(f"Error during execution: {e} + {e.with_traceback()}")
        return

    if len(errors) != 0:
        print(f"ERROR: execution completed with {len(errors)} errors")
        os._exit(1)

    print(f"DEBUG: execution completed with no errors, proceeding to bitmap validation")
    for error in validate_bitmap(bitmap, ports, blocklist_bitmap, subnet):
        print(f"Bitmap Validation Error: {error}")
        errors.append(error)

    # Final validation/summary
    if len(errors) == 0:
        print(f"Integration test passed successfully: {scanner_command}")
        return
    print(f"{len(errors)} Errors encountered during scan:\n")
    for error in errors:
        print(f"During-Scan Error: {error}")
    os._exit(1)


if __name__ == "__main__":
    base_scanner_cmd = [
        TOP_LEVEL_DIR + ZMAP_ABS_PATH, "--seed", "2", "-B", "200G", "--fast-dryrun", "-c", "0", "--batch", "256",
        "--verbosity", "1", "-X", "--blocklist-file", TOP_LEVEL_DIR + BLOCKLIST_FILE
    ]
    # 3 Port, Subnets of range /32 -> /2
    for i in range(32, 1, -1):
        subnet = f"128.0.0.0/{i}"
        scanner_cmd = base_scanner_cmd + ["-p", "80-81,443", "-T", "1", subnet]
        print(f"Running ZMap Command: {" ".join(scanner_cmd)}")
        ports_to_scan = [80,81,443]
        run_test(scanner_cmd, ports_to_scan, subnet)

    # Single Port, Subnets of range /32 -> /1
    for i in range(32, 0, -1):
        subnet = f"128.0.0.0/{i}"
        scanner_cmd = base_scanner_cmd + ["-p", "80", "-T", "1", subnet]
        print(f"Running ZMap Command: {" ".join(scanner_cmd)}")
        ports_to_scan = [80]
        run_test(scanner_cmd, ports_to_scan, subnet)

    # Single Port, Single Thread, Full IPv4
    scanner_cmd = base_scanner_cmd + ["-p", "80", "-T", "1"]
    print(f"Running ZMap Command: {" ".join(scanner_cmd)}")
    ports_to_scan = [80]
    run_test(scanner_cmd, ports_to_scan)

    # Single Port, 2 Thread, Full IPv4
    scanner_cmd = base_scanner_cmd + ["-p", "80", "-T", "2"]
    print(f"Running ZMap Command: {" ".join(scanner_cmd)}")
    ports_to_scan = [80]
    run_test(scanner_cmd, ports_to_scan)

    # Two Ports, Two Thread, Full IPv4
    scanner_cmd = base_scanner_cmd + ["-p", "80,443", "-T", "2"]
    print(f"Running ZMap Command: {" ".join(scanner_cmd)}")
    ports_to_scan = [80,443]
    run_test(scanner_cmd, ports_to_scan)
