import sh
import unittest

from sh import cut, grep, cat, wc, uniq, mv

zmap_std_args = [ "-b",
                  "configs/blacklist_shard.conf",
                  "--seed=1234",
                  "192.168.1.0/24",
                  "--dryrun",
                  "-c",
                  "1"
                ]

zmap = sh.Command("../src/zmap").bake(*zmap_std_args)

def shard_file_name(shards, threads):
    # Use naming conversion <shards>-t<threads>
    return ''.join([str(shards), '-t', str(threads)])

def output_file_name(shards, shard, threads):
    # Use naming convention: <shards>.<shard>-t<threads>
    return ''.join([str(shards), '.', str(shard), '-t', str(threads)])

def parse(filename, **kwargs):
    # cat outfile | grep ip | cut -d '|' -f 2 | cut -d ' ' -f 3 | cut -d '.' -f 4 | sort -n | wc -l
    return sh.sort(cut(cut(cut(grep(cat(filename), "ip"), d="|", f=2), d=" ", f=3), d=".", f=4), "-n", _out=kwargs.get("_out"))

class TestSharding(unittest.TestCase):

    NUM_IPS = 256

    def setUp(self):
        pass

    def takeDown(self):
        pass

    def _runTest(self, shards, max_threads):
        for threads in range(1, max_threads + 1):
            for shard in range(0, shards):
                with sh.sudo:
                    outfile = output_file_name(shards, shard, threads)
                    zmap(p=80, T=threads, shards=shards, shard=shard, _out="tempfile")
                    parse("tempfile", _out=outfile)
                    dup_lines = int(wc(uniq(cat(outfile), "-d"), "-l"))
                    self.assertEqual(dup_lines, 0)
                    shard_file = shard_file_name(shards, threads)
                    if shard == 0:
                        cat(outfile, _out=shard_file)
                    else:
                        cat(shard_file, outfile, _out="tempfile")
                        mv("tempfile", shard_file)

        for threads in range(1, max_threads + 1):
            shard_file = shard_file_name(shards, threads)
            num_lines = int(wc(cat(shard_file), "-l"))
            self.assertEqual(num_lines, TestSharding.NUM_IPS)
            dup_lines = int(wc(uniq(sh.sort(cat(shard_file), "-n"), "-d"), "-l"))
            self.assertEqual(dup_lines, 0)

    def testOneShard(self):
        # Test with one shard
        self._runTest(1, 4)


    def testTwoShards(self):
        self._runTest(2, 4)

if __name__ == '__main__':
    unittest.main()



