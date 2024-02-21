import ipaddress
import re
import subprocess
import sys

PACKET_SEP = "-" * 54


class Test:
    def __init__(self, port, subnet="", num_of_ips=-1, threads=-1):
        self.port = port
        self.subnet = subnet
        self.num_of_ips = num_of_ips
        self.threads = threads

    def run(self):
        args = ["../../src/zmap", "--dryrun"]
        args.extend(["-p", str(self.port)])
        if self.num_of_ips != -1:
            args.extend(["-n", str(self.num_of_ips)])
        if self.threads != -1:
            args.extend(["-T", str(self.threads)])
        test_output = subprocess.run(args, stdout=subprocess.PIPE).stdout.decode('utf-8')
        packets = parse_output_into_obj_list(test_output)
        return packets


def parse_output_into_obj_list(input: str) -> str:
    packets = []
    blocks = input.split(PACKET_SEP)
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        packets.append(parse_packet_string(block))

    return packets


# Define a function to parse a block of text
def parse_packet_string(block):
    # reg ex strings to find the fields we're interested in
    tcp_pattern = re.compile(r"tcp { source: (\d+) \| dest: (\d+) \| seq: (\d+) \| checksum: (.+?) }")
    ip_pattern = re.compile(r"ip { saddr: ([\d.]+) \| daddr: ([\d.]+) \| checksum: (.+?) }")
    eth_pattern = re.compile(r"eth { shost: ([\w:]+) \| dhost: ([\w:]+) }")

    tcp_match = tcp_pattern.search(block)
    ip_match = ip_pattern.search(block)
    eth_match = eth_pattern.search(block)
    packet = {}

    if tcp_match:
        packet["tcp"] = {
            "src_prot": int(tcp_match.group(1)),
            "dest_port": int(tcp_match.group(2)),
            "seq": int(tcp_match.group(3)),
            "checksum": tcp_match.group(4)
        }
    if ip_match:
        packet["ip"] = {
            "saddr": ip_match.group(1),
            "daddr": ip_match.group(2),
            "checksum": ip_match.group(3)
        }
    if eth_match:
        packet["eth"] = {
            "shost": eth_match.group(1),
            "dhost": eth_match.group(2)
        }

    if len(packet) == 0:
        # packet object is empty, cannot proceed
        sys.exit("packet output \"{}\" has no expected fields: \"tcp\", \"ip\", or \"eth\"".format(block))
    return packet


def test_num_returned_ips_equals_requested():
    # we'll try with different num_of_ips
    ip_reqs = [5, 65, 249]
    for num_of_ips in ip_reqs:
        t = Test(port=80, num_of_ips=num_of_ips)
        packet_list = t.run()
        assert len(packet_list) == num_of_ips
        for packet in packet_list:
            assert packet["tcp"]["dest_port"] == 80


def test_num_returned_ips_equals_requested_with_threads():
    # we'll try with different num_of_ips
    threads = [1, 2, 4, 5, 8, 34]
    num_of_ip_tests = [36, 1001]
    for thread in threads:
        for num_ips in num_of_ip_tests:
            t = Test(port=22, num_of_ips=num_ips, threads=thread)
            packet_list = t.run()
            assert len(packet_list) == num_ips
            for packet in packet_list:
                assert packet["tcp"]["dest_port"] == 22


## Shards
### Full coverage, without duplicates

## Subnet

## Seed

## Whitelist

## Blacklist

## --iplayer

## utils


def check_coverage(ip_list, subnet):
    """
    Checks if a list of IPs fully covers a subnet

    Args:
        ip_list (List(str)): List of IP addresses
        subnet (str): subnet in CIDR notation

    Returns:
        bool: True if all IPs in subnet are present in ip_list, False otherwise
    """
    # Convert the subnet string to an ipaddress object
    subnet = ipaddress.ip_network(subnet)

    # Convert the list of IPs to ipaddress objects
    ip_objects = [ipaddress.ip_address(ip) for ip in ip_list]

    # Check if all IPs in the subnet are covered by the IP list
    for ip in subnet.hosts():
        # TODO may want to build a lookup table or else this is a N^2 lookup problem
        if ip not in ip_objects:
            return False

    return True


if __name__ == "__main__":
    test_num_returned_ips_equals_requested()
