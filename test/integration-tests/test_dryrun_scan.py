import ipaddress
import math
import os
import time

import io_zmap
import utils


def test_num_returned_ips_equals_requested():
    # we'll try with different num_of_ips
    ip_reqs = [5, 65, 249]
    for num_of_ips in ip_reqs:
        t = io_zmap.Test(port=80, num_of_ips=num_of_ips)
        packet_list = t.run()
        assert len(packet_list) == num_of_ips
        for packet in packet_list:
            assert packet["tcp"]["dest"] == "80", "packets not sent to correct port"


def test_num_returned_ips_equals_requested_with_threads():
    # we'll try with different num_of_ips
    threads = [1, 2, 4, 5, 8, 34]
    num_of_ip_tests = [36, 1001]
    for thread in threads:
        for num_ips in num_of_ip_tests:
            t = io_zmap.Test(port=22, num_of_ips=num_ips, threads=thread)
            packet_list = t.run()
            assert len(packet_list) == num_ips
            for packet in packet_list:
                assert packet["tcp"]["dest"] == "22", "packets not sent to correct port"


def test_multi_port_single_ip():
    port_tests = ["22", "22,80,443,8080", "22-32", "22-32,80,443-445,8080,10"]
    expected_output = [utils.parse_ports_string(port_test) for port_test in port_tests]
    for test_iter in range(10):  # using iterations to check for bugs in shard code
        for port_test_index in range(len(port_tests)):
            packet_list = io_zmap.Test(port=port_tests[port_test_index], subnet="1.1.1.1", threads=1).run()
            # check that packet_list and expected_output are the same
            port_list = sorted([packet["tcp"]["dest"] for packet in packet_list])
            assert sorted(port_list) == sorted(expected_output[port_test_index]), "didn't scan all the expected ports"


def test_multi_port_with_subnet():
    port_tests = ["22", "22,80,443,8080", "22-32", "22-32,80,443-445,8080,10"]
    subnet = "1.1.1.0/29"
    expected_ports = [utils.parse_ports_string(port_test) for port_test in port_tests]
    expected_ips = set(str(ip) for ip in ipaddress.ip_network(subnet))
    for test_iter in range(10):  # using iterations to check for bugs in shard code
        for port_test_index in range(len(port_tests)):
            expected_port_set = set(expected_ports[port_test_index])
            packet_list = io_zmap.Test(port=port_tests[port_test_index], subnet=subnet, threads=1).run()
            assert len(packet_list) == len(expected_ips) * len(expected_ports[port_test_index])
            for packet in packet_list:
                assert packet["ip"]["daddr"] in expected_ips, "scanned IP not in subnet"
                assert packet["tcp"]["dest"] in expected_port_set, "scanned port not in expected ports"


def test_multi_port_with_subnet_and_threads():
    port_tests = ["22-32,80,443-445,8080,10"]
    subnet = "1.1.1.0/29"
    expected_ports = [utils.parse_ports_string(port_test) for port_test in port_tests]
    expected_ips = set(str(ip) for ip in ipaddress.ip_network(subnet))
    for thread_ct in range(1, 8):
        for test_iter in range(5):  # using iterations to check for bugs in shard code
            for port_test_index in range(len(port_tests)):
                expected_port_set = set(expected_ports[port_test_index])
                packet_list = io_zmap.Test(port=port_tests[port_test_index], subnet=subnet, threads=thread_ct).run()
                assert len(packet_list) == len(expected_ips) * len(expected_ports[port_test_index])
                for packet in packet_list:
                    assert packet["ip"]["daddr"] in expected_ips, "scanned IP not in subnet"
                    assert packet["tcp"]["dest"] in expected_port_set, "scanned port not in expected ports"


## Shards
def test_full_coverage_of_subnet_with_shards():
    shards_cts = [1, 4, 5, 8]
    subnet = "174.189.0.0/20"
    subnet_size = int(subnet.split("/")[1])
    seed = 123
    for shard_ct in shards_cts:
        ip_list = []
        for shard in range(shard_ct):
            packets = io_zmap.Test(subnet=subnet, shard=shard, shards=shard_ct, seed=seed).run()
            even_split_search_space = math.pow(2, 32 - subnet_size) / shard_ct
            assert abs(
                len(packets) - even_split_search_space) <= 100  # check that shards are splitting up the search space *relatively* evenly
            for packet in packets:
                ip_list.append(packet["ip"]["daddr"])
        assert utils.check_uniqueness_ip_list(ip_list), "scanned target IP multiple times"
        assert not len(ip_list) > math.pow(2, 32 - subnet_size), "scanned IPs other than those in the subnet"
        assert not len(ip_list) < math.pow(2, 32 - subnet_size), "did not scan enough IPs to cover the subnet"
        assert utils.check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"


## Subnet
def test_full_coverage_of_subnets():
    subnets = ["174.189.0.0/20", "65.189.78.0/24", "112.16.17.32/32"]
    for subnet in subnets:
        subnet_size = int(subnet.split("/")[1])
        packets = io_zmap.Test(subnet=subnet, threads=1).run()
        even_split_search_space = math.pow(2, 32 - subnet_size)
        ip_list = [packet["ip"]["daddr"] for packet in packets]
        assert utils.check_uniqueness_ip_list(ip_list), "scanned target IP multiple times"
        assert not len(ip_list) > math.pow(2, 32 - subnet_size), "scanned IPs other than those in the subnet"
        assert not len(ip_list) < math.pow(2, 32 - subnet_size), "did not scan enough IPs to cover the subnet"
        assert utils.check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"


def test_full_coverage_of_large_subnets():
    subnets = ["1.0.0.0/15"]
    for subnet in subnets:
        subnet_size = int(subnet.split("/")[1])
        packets = io_zmap.Test(subnet=subnet, threads=1).run()
        ip_list = [packet["ip"]["daddr"] for packet in packets]
        assert utils.check_uniqueness_ip_list(ip_list), "scanned target IP multiple times"
        assert not len(ip_list) > math.pow(2, 32 - subnet_size), "scanned IPs other than those in the subnet"
        assert not len(ip_list) < math.pow(2, 32 - subnet_size), "did not scan enough IPs to cover the subnet"
        assert utils.check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"


def test_multiple_subnets():
    subnets = ["174.189.0.0/24", "23.45.67.76/30"]
    expected_num_ips = math.pow(2, 32 - 24) + math.pow(2, 32 - 30)
    packets = io_zmap.Test(subnet=" ".join(subnets)).run()
    assert len(packets) == expected_num_ips
    ip_list = [packet["ip"]["daddr"] for packet in packets]
    for subnet in subnets:
        assert utils.check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"


def test_multiple_ips():
    ips = ["174.189.78.3", "1.1.1.1", "8.8.8.8"]
    expected_num_ips = len(ips)
    packets = io_zmap.Test(subnet=" ".join(ips), threads=1).run()
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
    packets = io_zmap.Test(subnet=" ".join(ips_and_subnets), threads=1).run()
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
        assert utils.check_coverage_of_ip_list(ip_list, subnet), "the entirety of the subnet was not scanned"


## Seed
def test_same_seed():
    """
    scan the same subnet twice with the same seed and check that the same IPs are scanned in the same order
    """
    subnet = "174.189.0.0/28"
    seed = 123
    # must use a single thread to have deterministic results
    packets1 = io_zmap.Test(subnet=subnet, seed=seed, threads=1).run()
    packets2 = io_zmap.Test(subnet=subnet, seed=seed, threads=1).run()
    assert len(packets1) == len(packets2)
    for i in range(len(packets1)):
        assert packets1[i]["ip"]["daddr"] == packets2[i]["ip"]["daddr"], "scanned IPs in different order with same seed"


def test_different_seeds():
    """
    scan the same subnet twice with different seeds and check that the IPs are scanned in a different order
    """
    subnet = "174.189.0.0/28"
    seed1 = 123
    seed2 = 987
    # must use a single thread to have deterministic results
    packets1 = io_zmap.Test(subnet=subnet, seed=seed1, threads=1).run()
    packets2 = io_zmap.Test(subnet=subnet, seed=seed2, threads=1).run()
    assert len(packets1) == len(packets2)
    are_packets_in_same_order = True
    for i in range(len(packets1)):
        if packets1[i]["ip"]["daddr"] != packets2[i]["ip"]["daddr"]:
            are_packets_in_same_order = False
            break
    assert not are_packets_in_same_order, "scanned IPs in same order with different seeds"


"""
--rate and --max-runtime
"""


def test_rate_limit():
    start_time = time.time()
    # scan 1k packets with a rate of 1k. The scan should stop after ~1 seconds
    # uses bounded_runtime_test to ensure the test doesn't run indefinitely should anything go wrong
    expected_runtime = 1
    utils.bounded_runtime_test(io_zmap.Test(threads=1, rate=1000, num_of_ips=1000))
    assert time.time() - start_time < expected_runtime + 0.5, "max_runtime was not respected"  # add small amt. buffer


def test_max_runtime():
    start_time = time.time()
    # scan full IPv4 space with a max runtime of 2 seconds. The scan should stop after 2 seconds
    # uses bounded_runtime_test to ensure the test doesn't run indefinitely should anything go wrong
    max_runtime = 1
    utils.bounded_runtime_test(io_zmap.Test(threads=1, max_runtime=max_runtime))
    assert time.time() - start_time < max_runtime + 0.5, "max_runtime was not respected"  # add small amt. buffer


def test_max_runtime_and_rate():
    start_time = time.time()
    # scan full IPv4 space with a max runtime of 1 seconds and a rate of 1000. The scan should stop after 1 seconds
    # uses bounded_runtime_test to ensure the test doesn't run indefinitely should anything go wrong
    expected_runtime = 1 + 0.5
    packets = utils.bounded_runtime_test(io_zmap.Test(threads=1, max_runtime=1, rate=1000))
    assert time.time() - start_time < expected_runtime, "scan did not stop after ~1 seconds"
    assert len(packets) > 0, "no packets were sent"
    assert len(packets) < 1100, "rate was not respected"  # add small buffer


"""
--source-port and --source-ip
"""


def test_source_port_option():
    """
    scan using various single and multiple source ports and ensure the correct source ports are used
    """
    source_port_tests = [
        "80",  # single port
        "22-24",  # multiple ports
    ]
    for source_port in source_port_tests:
        packets = io_zmap.Test(threads=1, source_port=source_port, num_of_ips=500).run()
        expected_ports_to_packets_sent = {}
        if "-" not in source_port:
            # using a single source port
            expected_ports_to_packets_sent[source_port] = 0
        else:
            # using a source port range
            expected_ports = utils.enumerate_port_range(source_port)
            for port in expected_ports:
                expected_ports_to_packets_sent[port] = 0
        for packet in packets:
            assert packet.get("tcp")
            assert packet["tcp"]["source"] in expected_ports_to_packets_sent, "incorrect source port used"
            expected_ports_to_packets_sent[packet["tcp"]["source"]] += 1
        # check that all source ports used at least once
        for port, uses in expected_ports_to_packets_sent.items():
            assert uses > 0, "source port {} not used".format(port)


def test_source_ip_option():
    """
    scan using various source IPs and ensure the correct source IPs are used
    """
    source_ip_tests = [
        "134.23.98.23",  # single IP
        "189.23.45.32-189.23.45.34",  # range
    ]
    for source_ip in source_ip_tests:
        packets = io_zmap.Test(threads=1, source_ip=source_ip, num_of_ips=1000).run()
        expected_ips_to_packets_sent = {}
        if "-" not in source_ip:
            # using a single source IP
            expected_ips_to_packets_sent[source_ip] = 0
        else:
            # using a source IP range
            expected_ips = utils.enumerate_IP_range(source_ip)
            for ip in expected_ips:
                expected_ips_to_packets_sent[ip] = 0
        for packet in packets:
            assert packet.get("ip")
            # check if source_ip is a single IP or a subnet
            assert packet["ip"]["saddr"] in expected_ips_to_packets_sent, "incorrect source IP used"
            expected_ips_to_packets_sent[packet["ip"]["saddr"]] += 1
        # check that all source ips used at least once
        for ip, uses in expected_ips_to_packets_sent.items():
            assert uses > 0, "source IP {} not used".format(ip)


def test_source_mac_option():
    """
    scan using various source MACs and ensure the correct source MACs are used
    """
    subnet = "45.23.128.0/30"
    source_mac_tests = ["00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff", "01:23:45:67:89:ab"]
    for source_mac in source_mac_tests:
        packets = io_zmap.Test(threads=1, source_mac=source_mac, subnet=subnet).run()
        for packet in packets:
            assert packet.get("eth")
            assert packet["eth"]["shost"] == source_mac, "incorrect source MAC used"


"""
--probes
"""


def probes_helper(probes: int, subnet: str):
    packets = io_zmap.Test(subnet=subnet, threads=1, probes=str(probes)).run()
    if probes == 0:
        assert len(packets) == 0, "packets were sent when no probes were specified"
        return  # no need to check anything else
    # count how many packets were sent to each IP
    ip_to_num_packets = {}
    for packet in packets:
        ip = packet["ip"]["daddr"]
        if ip in ip_to_num_packets:
            ip_to_num_packets[ip] += 1
        else:
            ip_to_num_packets[ip] = 1
    for expected_ip in ipaddress.ip_network(subnet):
        assert ip_to_num_packets[str(expected_ip)], "IP not scanned"
        assert ip_to_num_packets[str(expected_ip)] == probes, "incorrect number of packets sent"


def test_probes_option():
    """
    scan using various numbers of probes and ensure the correct number of packets are sent
    """
    probe_tests = [0, 1, 2, 3, 4, 8, 13, 21]
    subnets = [
        "178.1.128.0/28",
        "45.23.128.0/30",
        "69.2.1.0/27"
    ]
    for subnet_test in subnets:
        for probe_test in probe_tests:
            probes_helper(probe_test, subnet_test)


"""
--list-of-ips
"""


def test_list_of_ips_option():
    """
    scan using a list of IPs and ensure the correct IPs are scanned
    """
    assert True == False, "test not implemented"


"""
---allowlist-file
"""

allowed_subnets = [
    "178.1.1.0/30",
    "173.31.16.0/31",
    "103.0.113.0/32"
]


def test_allowlist():
    """
    scan using an allowlist and ensure only IPs in the allowlist are scanned
    """

    with open("allowlist.txt", "w") as file:
        for subnet in allowed_subnets:
            file.write(subnet + "\n")
    expected_ips = set(str(ip) for subnet in allowed_subnets for ip in ipaddress.ip_network(subnet))

    packets = io_zmap.Test(threads=1, allowlist_file="allowlist.txt").run()
    actual_packet_ips = set(packet["ip"]["daddr"] for packet in packets)
    assert actual_packet_ips == expected_ips, "scanned IPs not in the allowlist"

    # cleanup
    os.remove("allowlist.txt")


def test_allowlist_with_subnet():
    """
    per the code: "allowlist: both a allowlist file and destination addresses were specified. The union of these two
        sources will be utilized."
    Test will ensure that both the allowlist file and the subnet are used to scan the correct IPs
    """
    scanning_subnet = "34.1.128.0/21"

    with open("allowlist.txt", "w") as file:
        for subnet in allowed_subnets:
            file.write(subnet + "\n")
    expected_ips = set(str(ip) for subnet in allowed_subnets for ip in ipaddress.ip_network(subnet))
    # append the IPs in the scanning subnet to the expected IPs
    expected_ips = expected_ips.union(set(str(ip) for ip in ipaddress.ip_network(scanning_subnet)))

    packets = io_zmap.Test(threads=1, allowlist_file="allowlist.txt", subnet=scanning_subnet).run()
    actual_packet_ips = set(packet["ip"]["daddr"] for packet in packets)

    assert actual_packet_ips == expected_ips, "scanned IPs not in the allowlist"

    # cleanup
    os.remove("allowlist.txt")


"""
--blocklist-file
"""


def blocklist_helper(blocklist_subnet_str: str, scanned_subnet_str: str):
    blocklist_subnet = ipaddress.ip_network(blocklist_subnet_str)
    scanned_subnet = ipaddress.ip_network(scanned_subnet_str)

    blocklist_ips = set(str(ip) for ip in blocklist_subnet)
    all_ips = set(str(ip) for ip in scanned_subnet)
    unblocked_ips = all_ips - blocklist_ips

    with open("blocklist.txt", "w") as file:
        file.write(blocklist_subnet_str)

    packets = io_zmap.Test(subnet=scanned_subnet_str, threads=1, blocklist_file="blocklist.txt").run()
    actual_packet_ips = {packet["ip"]["daddr"] for packet in packets}
    for ip in blocklist_ips:
        assert ip not in actual_packet_ips, "blocked IP was scanned"
    for ip in unblocked_ips:
        assert ip in actual_packet_ips, "unblocked IP was not scanned"

    os.remove("blocklist.txt")


def test_blocklist_partially_covers_subnet():
    """
    scan a subnet partially covered by a blocklist and ensure only IPs not in the blocklist are scanned
    """
    tests = [
        ("1.1.1.128/26", "1.1.1.0/24"),
        ("100.64.0.0/26", "100.64.0.0/24"),
        ("172.31.16.0/28", "172.31.16.0/26"),
        ("203.0.113.128/27", "203.0.113.0/24"),
        ("198.51.100.16/29", "198.51.100.0/25")
    ]
    for blocklist_subnet_str, scanned_subnet_str in tests:
        blocklist_helper(blocklist_subnet_str, scanned_subnet_str)


def test_blocklist_does_not_cover_subnet():
    tests = [
        ("10.0.0.0/24", "10.0.1.0/24"),
        ("192.0.2.0/24", "192.0.3.0/24"),
        ("172.16.0.0/24", "172.16.1.0/24"),
        ("203.0.113.0/24", "203.0.114.0/24"),
        ("198.51.100.0/24", "198.51.101.0/24")
    ]
    for blocklist_subnet_str, scanned_subnet_str in tests:
        blocklist_helper(blocklist_subnet_str, scanned_subnet_str)


def test_blocklist_fully_covers_subnet():
    blocklist_helper("10.0.0.0/24", "10.0.0.0/24")


## --iplayer
def test_ip_layer_option():
    ips = ["174.189.78.3", "1.1.1.1", "8.8.8.8"]
    # 3 IPs and 2 subnets, 16 and 4 IPs, respectively
    packets = io_zmap.Test(subnet=" ".join(ips), threads=1, iplayer=True).run()
    assert len(packets) == len(ips)
    for packet in packets:
        # ensure proper fields are present
        assert packet["ip"]
        assert packet["tcp"]
        assert not packet.get("eth")

    ip_list = [packet["ip"]["daddr"] for packet in packets]
    for ip in ips:
        assert ip in ip_list, "an IP was not scanned"
