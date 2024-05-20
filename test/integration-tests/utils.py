import ipaddress
import re

from random import random
from timeout_decorator import timeout
import typing

import zmap_wrapper


def enumerate_IP_range(ip_range: str):
    """
    Args:
        ip_range (str): IP range in notation "start_ip-end_ip"

    Returns:
        List[str]: List of IP addresses in the range
    """
    start_ip, end_ip = ip_range.split("-")
    start_ip = ipaddress.ip_address(ip_range.split("-")[0])
    end_ip = ipaddress.ip_address(ip_range.split("-")[1])
    return [str(ipaddress.ip_address(ip)) for ip in range(int(start_ip), int(end_ip) + 1)]


def test_enumerate_IP_range():
    ip_range = "189.23.45.32-189.23.45.34"  # range
    expected_ips = [
        "189.23.45.32",
        "189.23.45.33",
        "189.23.45.34",
    ]
    assert enumerate_IP_range(ip_range) == expected_ips


def enumerate_port_range(port_range: str):
    """
    Args:
        port_range (str): Port range in notation "start_port-end_port"

    Returns:
        List[int]: List of ports in the range
    """
    start_port, end_port = port_range.split("-")
    return list(str(i) for i in range(int(start_port), int(end_port) + 1))


def test_enumerate_port_range():
    port_range = "22-25"  # range
    expected_ports = ["22", "23", "24", "25"]
    assert enumerate_port_range(port_range) == expected_ports


## utils
def check_uniqueness_ip_list(ip_list):
    """
    Args:
        ip_list (List(str)): List of IP addresses

    Returns:
        bool: True if all IPs are unique, False otherwise
    """
    return len(ip_list) == len(set(ip_list))


def test_check_uniqueness_ip_list():
    ip_list = [
        "1.1.1.1",
        "1.1.1.1"
    ]
    assert not check_uniqueness_ip_list(ip_list)
    ip_list = ["1.1.1.1"]
    assert check_uniqueness_ip_list(ip_list)


def check_coverage_of_ip_list(ip_list: typing.List[str], subnet: str):
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


def test_check_coverage_of_ip_list():
    ip_list = [
        "192.168.1.0",
        "192.168.1.1",
        "192.168.1.2",
        "192.168.1.3",
    ]
    subnet = "192.168.1.0/30"
    assert check_coverage_of_ip_list(ip_list, subnet)
    ip_list = [
        "192.168.1.0",
        "192.168.1.2",
        "192.168.1.3",
    ]
    assert not check_coverage_of_ip_list(ip_list, subnet)


def parse_ports_string(port_string) -> typing.List[str]:
    """
    Parses a string of ports in the format "22-25,80,443" into a list of individual ports
    Args:
        port_string (str): String of ports in the format "22-25,80,443"
    Returns:
        List[str]: List of individual ports
    """
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

    return [str(port) for port in ports]


def test_parse_ports_string():
    tests = {
        "22": ["22"],
        "22-25": ["22", "23", "24", "25"],
        "22,80": ["22", "80"],
        "24-28,443,34,8080-8085": ["24", "25", "26", "27", "28", "443", "34", "8080",
                                   "8081", "8082", "8083", "8084", "8085"]
    }
    for t in tests:
        output = parse_ports_string(t)
        expected_output = tests[t]
        assert len(output) == len(expected_output), "lists don't match in length"
        output.sort()
        expected_output.sort()
        for i in range(len(output)):
            assert output[i] == expected_output[i], "lists do not match"


@timeout(5)  # bounding the runtime of the test so we don't get a stalled Github action should a failure occur in ZMap
def bounded_runtime_test(t: zmap_wrapper.Wrapper):
    return t.run()


def write_ips_to_file(num_of_ips, filename):
    """
    Writes a list of public, non-blocked IPs to a file
    Args:
        num_of_ips (int): Number of IPs to write to the file
        filename (str): File to write the IPs to
    Returns:
        List of IPs written to the file, as strings
    """
    subnet_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b'
    # read in blocked subnets in file "blocklist.conf" into a list
    blocked_subnets = []
    with open("../../conf/blocklist.conf", "r") as file:
        for line in file:
            if not line.startswith("#") and "/" in line:
                # need to use a regex to pull out the subnet
                subnet = re.findall(subnet_pattern, line.strip())
                if subnet:
                    blocked_subnets.append(subnet[0])

    # generate a list of num_of_ips random, non-blocked public IPs
    ips = set()
    for _ in range(num_of_ips):
        while True:
            ip = str(ipaddress.IPv4Address(int(2 ** 32 * random())))
            # ensure the IP is not in the blocklist
            if any(ipaddress.ip_address(ip) in ipaddress.ip_network(subnet) for subnet in blocked_subnets):
                # IP is blocked
                continue
            if ipaddress.ip_address(ip).is_global and not ipaddress.ip_address(ip).is_reserved and ip not in ips:
                # found a good IP
                ips.add(ip)
                break
    # write the IPs to a file
    with open(filename, "w") as file:
        for ip in ips:
            file.write(ip + "\n")

    return ips
