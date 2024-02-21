import ipaddress
import math
import re
import subprocess
import sys

PACKET_SEP = "-" * 54


class Test:
    def __init__(self, port="80", subnet="", num_of_ips=-1, threads=-1, shards=-1, shard=-1, seed=-1, iplayer=False):
        self.port = port
        self.subnet = subnet
        self.num_of_ips = num_of_ips
        self.threads = threads
        self.shards = shards
        self.shard = shard
        self.seed = seed
        self.iplayer = iplayer

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
        if self.iplayer:
            args.extend(["--iplayer"])

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


def parse_ports_string(port_string):
    ports = []
    # Regular expression to match individual ports or port ranges
    pattern = re.compile(r'(\d+)-(\d+)|(\d+)')
    matches = pattern.findall(port_string)

    for match in matches:
        if match[0]:  # If it's a port range
            start = int(match[0])
            end = int(match[1])
            ports.extend(range(start, end + 1))
        else:  # If it's a single port
            ports.append(int(match[2]))

    return ports


def test_parse_ports_string():
    tests = {
        "22": [22],
        "22-25": [22, 23, 24, 25],
        "22,80": [22, 80],
        "24-28,443,34,8080-8085": [24, 25, 26, 27, 28, 34, 443, 8080, 8081, 8082, 8083, 8084, 8085],
    }
    for t in tests:
        output = parse_ports_string(t)
        expected_output = tests[t]
        assert len(output) == len(expected_output), "lists don't match in length"
        output.sort()
        expected_output.sort()
        for i in range(len(output)):
            assert output[i] == expected_output[i], "lists do not match"


def test_num_returned_ips_equals_requested():
    # we'll try with different num_of_ips
    ip_reqs = [5, 65, 249]
    for num_of_ips in ip_reqs:
        t = Test(port=80, num_of_ips=num_of_ips)
        packet_list = t.run()
        assert len(packet_list) == num_of_ips
        for packet in packet_list:
            assert packet["tcp"]["dest_port"] == 80, "packets not sent to correct port"


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
                assert packet["tcp"]["dest_port"] == 22, "packets not sent to correct port"


def test_multi_port():
    port_tests = ["22", "22,80", "22,80,443,8080", "22-32", "22-32,80,443-445,8080,10"]
    expected_output = [parse_ports_string(port_test) for port_test in port_tests]
    for i in range(len(port_tests)):
        # TODO leaving this test failing until I get an answer from the team
        # packet_list = Test(port=port_tests[i], subnet="1.1.1.1").run()
        packet_list = Test(port=port_tests[i], num_of_ips=1).run()
        # check that packet_list and expected_output are the same
        port_list = [packet["tcp"]["dest_port"] for packet in packet_list]
        assert len(port_list) == len(expected_output[i])
        port_list.sort()
        expected_output[i].sort()
        for j in range(len(port_list)):
            assert port_list[j] == expected_output[i][j]


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
            assert abs(
                len(packets) - even_split_search_space) <= 100  # check that shards are splitting up the search space *relatively* evenly
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


def test_full_coverage_of_large_subnets():
    subnets = ["1.0.0.0/15"]
    for subnet in subnets:
        subnet_size = int(subnet.split("/")[1])
        packets = Test(subnet=subnet, threads=1).run()
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


def test_multiple_ips_and_subnets():
    ips = ["174.189.78.3", "1.1.1.1", "8.8.8.8"]
    subnets = ["174.189.0.0/28", "23.45.67.76/30"]
    ips_and_subnets = ips + subnets
    # 3 IPs and 2 subnets, 16 and 4 IPs, respectively
    expected_num_ips = 3 + math.pow(2, 32 - 28) + math.pow(2, 32 - 30)
    packets = Test(subnet=" ".join(ips_and_subnets), threads=1).run()
    assert len(packets) == expected_num_ips
    for packet in packets:
        # ensure proper fields are present
        assert packet.get("tcp")
        assert packet.get("ip")
        assert packet.get("eth")

    ip_list = [packet["ip"]["daddr"] for packet in packets]
    for ip in ips:
        assert ip in ip_list, "an IP was not scanned"
    for subnet in subnets:
        assert check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"


## Seed

## Whitelist

## Blacklist

## --iplayer
def test_ip_layer_option():
    ips = ["174.189.78.3", "1.1.1.1", "8.8.8.8"]
    # 3 IPs and 2 subnets, 16 and 4 IPs, respectively
    packets = Test(subnet=" ".join(ips), threads=1, iplayer=True).run()
    assert len(packets) == len(ips)
    for packet in packets:
        # ensure proper fields are present
        assert packet["ip"]
        assert packet["tcp"]
        assert not packet.get("eth")

    ip_list = [packet["ip"]["daddr"] for packet in packets]
    for ip in ips:
        assert ip in ip_list, "an IP was not scanned"


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
