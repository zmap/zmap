import unittest
import subprocess
import os
import sys

executable_path = None

class ZBlocklistTest(unittest.TestCase):

    BLOCKLIST = [
        "10.0.0.0/8         # private subnet",
        "192.168.0.0/16     # private subnet",
        "128.255.0.0/16     # university of iowa",
        "141.212.120.0/24   # halderman lab"
    ]

    ALLOWLIST = [
        "141.212.0.0/16    # university of michigan",
    ]

    IPS = [
        "61.193.80.24",
        "195.19.1.6",
        "114.34.253.25",
        "180.69.174.9",
        "38.134.130.203",
        "192.168.1.50",
        "98.125.221.180",
        "197.160.60.150",
        "47.139.63.128",
        "95.224.78.221",
        "170.114.52.252",
        "10.0.0.5",
        "128.255.134.1",
        "141.212.120.10",
        "141.212.12.6"
    ]

    IPS_MINUS_BL = [
        "61.193.80.24",
        "195.19.1.6",
        "114.34.253.25",
        "180.69.174.9",
        "38.134.130.203",
        "98.125.221.180",
        "197.160.60.150",
        "47.139.63.128",
        "95.224.78.221",
        "170.114.52.252",
        "141.212.12.6"
    ]

    WL_IPS = [
        "141.212.120.10",
        "141.212.12.6"
    ]

    WL_IPS_MINUS_BL = [
        "141.212.12.6"
    ]

    COMMENT_STRS = [
        "# some comment here",
        " # some comment here",
        ",google.com,data",
        "\t#some comment here"
    ]

    def setUp(self):
        global executable_path
        self.path = executable_path
        with open("/tmp/blocklist", "w") as fd:
            for line in self.BLOCKLIST:
                fd.write("%s\n" % line)
        with open("/tmp/allowlist", "w") as fd:
            for line in self.ALLOWLIST:
                fd.write("%s\n" % line)
        with open("/tmp/ips", "w") as fd:
            for line in self.IPS:
                fd.write("%s\n" % line)
        with open("/tmp/ips-commented", "w") as fd:
            for line in self.IPS:
                for comment in self.COMMENT_STRS:
                    fd.write("%s%s\n" % (line, comment))

    def tearDown(self):
        if os.path.exists("/tmp/blocklist"):
            os.remove("/tmp/blocklist")
        if os.path.exists("/tmp/allowlist"):
            os.remove("/tmp/allowlist")
        if os.path.exists("/tmp/ips"):
            os.remove("/tmp/ips")
        if os.path.exists("/tmp/ips-commented"):
            os.remove("/tmp/ips-commented")


    def execute(self, allowlist, blocklist, ipsfile="/tmp/ips", numtimestocat=1):
        cmd = "cat"
        for _ in range(0, numtimestocat):
            cmd += " %s" % ipsfile
        cmd += " | %s" % self.path
        if allowlist:
            cmd = cmd + " -w %s" % allowlist
        if blocklist:
            cmd = cmd + " -b %s" % blocklist
        results = subprocess.check_output(cmd, shell=True)
        ips = results.rstrip().split("\n")
        return ips

    def testValidBlocklist(self):
        res = self.execute(None, "/tmp/blocklist")
        self.assertEqual(set(res), set(self.IPS_MINUS_BL))

    def testValidAllowlist(self):
        res = self.execute("/tmp/allowlist", None)
        self.assertEqual(set(res), set(self.WL_IPS))

    def testValidAllowAndBlockList(self):
        res = self.execute("/tmp/allowlist", "/tmp/blocklist")
        self.assertEqual(set(res), set(self.WL_IPS_MINUS_BL))

    def testDuplicateChecking(self):
        res = self.execute(None, "/tmp/blocklist", numtimestocat=5)
        self.assertEqual(len(res), len(self.IPS_MINUS_BL))
        self.assertEqual(set(res), set(self.IPS_MINUS_BL))

    def testCommentCharacters(self):
        res = self.execute(None, "/tmp/blocklist", ipsfile="/tmp/ips-commented")
        self.assertEqual(set(res), set(self.IPS_MINUS_BL))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("USAGE: %s zblocklist" % sys.argv[0])
        sys.exit(1)
    executable_path = sys.argv[1]
    assert(os.path.exists(executable_path))
    unittest.main(argv=sys.argv[:1])
