import re
import subprocess
import sys

PACKET_SEP = "-" * 54


class Wrapper:
    def __init__(self, port="80", subnet="", num_of_ips=-1, threads=-1, shards=-1, shard=-1, seed=-1, iplayer=False,
                 dryrun=True, output_file="", max_runtime=-1, max_cooldown=-1, blocklist_file="", allowlist_file="",
                 list_of_ips_file="", probes="", source_ip="", source_port="", source_mac="", rate=-1, max_targets=""):
        self.port = port
        self.subnet = subnet
        self.num_of_ips = num_of_ips
        self.threads = threads
        self.shards = shards
        self.shard = shard
        self.seed = seed
        self.iplayer = iplayer
        self.dryrun = dryrun
        self.output_file = output_file
        self.max_runtime = max_runtime
        self.max_cooldown = max_cooldown
        self.blocklist_file = blocklist_file
        self.allowlist_file = allowlist_file
        self.list_of_ips_file = list_of_ips_file
        self.probes = probes
        self.source_ip = source_ip
        self.source_port = source_port
        self.source_mac = source_mac
        self.rate = rate
        self.max_targets = max_targets


    def run(self):
        args = ["../../src/zmap"]
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
        if self.dryrun:
            args.extend(["--dryrun"])
        if self.output_file:
            args.extend(["-o", self.output_file])
        if self.max_runtime != -1:
            args.extend(["--max-runtime="+ str(self.max_runtime)])
        if self.max_cooldown != -1:
            args.extend(["-c", str(self.max_cooldown)])
        if self.blocklist_file:
            args.extend(["--blocklist-file=" + self.blocklist_file])
        if self.allowlist_file:
            args.extend(["--allowlist-file=" + self.allowlist_file])
        if self.list_of_ips_file:
            args.extend(["--list-of-ips-file=" + self.list_of_ips_file])
        if self.probes:
            args.extend(["--probes=" + self.probes])
        if self.source_ip:
            args.extend(["--source-ip=" + self.source_ip])
        if self.source_port:
            args.extend(["--source-port=" + self.source_port])
        if self.source_mac:
            args.extend(["--source-mac=" + self.source_mac])
        if self.rate != -1:
            args.extend(["--rate=" + str(self.rate)])
        if self.max_targets != "":
            args.extend(["--max-targets=" + str(self.max_targets)])

        test_output = subprocess.run(args, stdout=subprocess.PIPE).stdout.decode('utf-8')
        packets = parse_output_into_obj_list(test_output)
        return packets


def parse_output_into_obj_list(zmap_output: str):
    """
    Chunks the entire ZMap output stream into individual packet outputs, and passes this to parse_packet_string
    """
    packets = []
    blocks = zmap_output.split(PACKET_SEP)
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        packets.append(parse_packet_string(block))

    return packets


def parse_packet_string(block):
    """
    Parses a string of packet output from zmap into a dictionary object storing the packet's fields
    """
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
            "source": tcp_match.group(1),
            "dest": tcp_match.group(2),
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
