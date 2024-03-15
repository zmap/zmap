import os

import zmap_wrapper

output_file_path = "output.txt"

def test_scan_known_good_ips():
    """
    This test will scan (not dry run) known active IPs and check that they are all scanned
    """
    known_active_ips = ["1.1.1.1", "8.8.8.8"]
    # create file called "output.txt" in current directory
    with open(output_file_path, 'w') as file:
        file.write("")
    # using known dns resolvers to make this test deterministic
    t = zmap_wrapper.Wrapper(dryrun=False, port=53, subnet=" ".join(known_active_ips), threads=1, output_file=output_file_path, max_cooldown=3)
    t.run()
    # read the file into a list of IPs
    ips = []
    with open(output_file_path, 'r') as file:
        for line in file:
            ips.append(line.strip())

    for ip in known_active_ips:
        assert ip in ips, "an expected IP was not scanned"
    # clean up
    os.remove(output_file_path)


def test_scan_known_good_ips_with_iplayer():
    """
    This test will scan (not dry run) known active IPs and check that they are all scanned
    Uses the --iplayer flag to test only sending IP packets (lets the OS compose the Ethernet frame)
    """
    known_active_ips = ["1.1.1.1", "8.8.8.8"]
    # create file called "output.txt" in current directory
    with open(output_file_path, 'w') as file:
        file.write("")
    # using known dns resolvers to make this test deterministic
    t = zmap_wrapper.Wrapper(dryrun=False, port=53, subnet=" ".join(known_active_ips), threads=1, output_file=output_file_path, max_cooldown=3, iplayer=True)
    t.run()
    # read the file into a list of IPs
    ips = []
    with open(output_file_path, 'r') as file:
        for line in file:
            ips.append(line.strip())

    for ip in known_active_ips:
        assert ip in ips, "an expected IP was not scanned"
    # clean up
    os.remove(output_file_path)

