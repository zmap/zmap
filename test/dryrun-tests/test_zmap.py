import ipaddress
import math
import re
import subprocess
import sys

PACKET_SEP = "-" * 54


class Test:
    def __init__(self, port=80, subnet="", num_of_ips=-1, threads=-1, shards=-1, shard=-1, seed=-1):
        self.port = port
        self.subnet = subnet
        self.num_of_ips = num_of_ips
        self.threads = threads
        self.shards = shards
        self.shard = shard
        self.seed = seed

    def run(self):
        args = ["../../src/zmap", "--dryrun"]
        args.extend(["-p", str(self.port)])
        if self.subnet:
            args.extend(self.subnet.split())
        if self.num_of_ips != -1:
            args.extend(["-n", str(self.num_of_ips)])
        if self.threads != -1:
            args.extend(["-T", str(self.threads)])
        if self.shards != -1:
            args.extend(["--shards=" + str(self.shards)])
        if self.shard != -1:
            args.extend(["--shard=" + str(self.shard)])
        if self.seed != -1:
            args.extend(["--seed=" + str(self.seed)])

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
def test_full_coverage_of_subnet_with_shards():
    shards_cts = [1, 4, 5, 8]
    subnet = "174.189.0.0/20"
    subnet_size = int(subnet.split("/")[1])
    seed = 123
    for shard_ct in shards_cts:
        ip_list = []
        for shard in range(shard_ct):
            packets = Test(subnet=subnet, shard=shard, shards=shard_ct, seed=seed).run()
            even_split_search_space = math.pow(2, 32 - subnet_size) / shard_ct
            assert abs(len(packets) - even_split_search_space) <= 100 # check that shards are splitting up the search space *relatively* evenly
            for packet in packets:
                ip_list.append(packet["ip"]["daddr"])
        assert check_uniqueness_ip_list(ip_list), "scanned target IP multiple times"
        assert not len(ip_list) > math.pow(2, 32 - subnet_size), "scanned IPs other than those in the subnet"
        assert not len(ip_list) < math.pow(2, 32 - subnet_size), "did not scan enough IPs to cover the subnet"
        assert check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"


## Subnet
def test_full_coverage_of_subnets():
    subnets = ["174.189.0.0/20", "65.189.78.0/24", "112.16.17.32/32"]
    for subnet in subnets:
        subnet_size = int(subnet.split("/")[1])
        packets = Test(subnet=subnet, threads=1).run()
        even_split_search_space = math.pow(2, 32 - subnet_size)
        ip_list = [packet["ip"]["daddr"] for packet in packets]
        assert check_uniqueness_ip_list(ip_list), "scanned target IP multiple times"
        assert not len(ip_list) > math.pow(2, 32 - subnet_size), "scanned IPs other than those in the subnet"
        assert not len(ip_list) < math.pow(2, 32 - subnet_size), "did not scan enough IPs to cover the subnet"
        assert check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"

def test_multiple_subnets():
    subnets = ["174.189.0.0/24", "23.45.67.76/30"]
    expected_num_ips = math.pow(2, 32 - 24) + math.pow(2, 32 - 30)
    packets = Test(subnet=" ".join(subnets)).run()
    assert len(packets) == expected_num_ips
    ip_list = [packet["ip"]["daddr"] for packet in packets]
    for subnet in subnets:
        assert check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"

def test_multiple_ips():
    ips = ["174.189.78.3", "1.1.1.1", "8.8.8.8"]
    expected_num_ips = len(ips)
    packets = Test(subnet=" ".join(ips), threads=1).run()
    assert len(packets) == expected_num_ips
    ip_list = [packet["ip"]["daddr"] for packet in packets]
    for ip in ips:
        assert ip in ip_list, "an IP was not scanned"




## Seed

## Whitelist

## Blacklist

## --iplayer

## utils



def check_uniqueness_ip_list(ip_list):
    """
    Args:
        ip_list (List(str)): List of IP addresses

    Returns:
        bool: True if all IPs are unique, False otherwise
    """
    return len(ip_list) == len(set(ip_list))

def check_coverage_of_ip_list(ip_list, subnet):
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
    ip_objects = {ipaddress.ip_address(ip) for ip in ip_list}

    # Check if all IPs in the subnet are covered by the IP list
    for ip in subnet.hosts():
        if ip not in ip_objects:
            return False

    return True


# TODO remove this debugging code
if __name__ == "__main__":
    test_multiple_subnets()
