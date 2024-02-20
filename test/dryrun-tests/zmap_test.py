import json
import subprocess
import re
import sys

PACKET_SEP = "-" * 52
class Test:
    def __init__(self, port, subnet="", num_of_ips=-1):
        self.port = port
        self.subnet = subnet
        self.num_of_ips = num_of_ips

    def run(self):
        args = ["../../src/zmap", "--dryrun"]
        args.extend(["-p", str(self.port)])
        if self.num_of_ips != -1:
            args.extend(["-n", str(self.num_of_ips)])
        test_output = subprocess.run(args, stdout=subprocess.PIPE).stdout.decode('utf-8')
        json_output = parse_output_into_json(test_output)
        return test_output

def parse_output_into_json(input:str)->str:
    packets = []
    blocks = input.split(PACKET_SEP)
    for block in blocks:
        block = block.strip()
        block = "hello"
        block_obj = parse_packet_string(block)


    return blocks[0]


# Define a function to parse a block of text
def parse_packet_string(block):
    # reg ex strings to find the fields we're interested in
    tcp_pattern = re.compile(r"tcp { source: (\d+) \| dest: (\d+) \| seq: (\d+) \| checksum: (.+?) }")
    ip_pattern = re.compile(r"ip { saddr: ([\d.]+) \| daddr: ([\d.]+) \| checksum: (.+?) }")
    eth_pattern = re.compile(r"eth { shost: ([\w:]+) \| dhost: ([\w:]+) }")

    tcp_match = tcp_pattern.search(block)
    ip_match = ip_pattern.search(block)
    eth_match = eth_pattern.search(block)
    packet ={}

    if tcp_match:
        packet["tcp"] = {
                "source": int(tcp_match.group(1)),
                "dest": int(tcp_match.group(2)),
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





