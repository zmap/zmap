import os
import re

import zmap_wrapper


OUTPUT = "ja4ts_output.txt"
JA4TS_RE = re.compile(r"^[0-9]+_[0-9-]*_[0-9]+_[0-9]+$")


def test_ja4ts_field_well_formed():
    """
    Scan known-active DNS resolvers on port 53 with --probe-args=ja4ts and
    verify that each SYN-ACK row carries a well-formed ja4ts fingerprint.
    """
    targets = ["1.1.1.1", "8.8.8.8"]
    with open(OUTPUT, "w") as f:
        f.write("")
    t = zmap_wrapper.Wrapper(
        dryrun=False,
        port=53,
        subnet=" ".join(targets),
        threads=1,
        output_file=OUTPUT,
        max_cooldown=3,
        probe_args="ja4ts",
        output_fields="saddr,ja4ts,classification",
    )
    t.run()
    saw_synack = False
    try:
        with open(OUTPUT) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("saddr"):
                    continue
                parts = line.split(",")
                assert len(parts) == 3, f"unexpected line shape: {line!r}"
                saddr, ja4ts, cls = parts
                if cls != "synack":
                    continue
                saw_synack = True
                assert JA4TS_RE.match(ja4ts), (
                    f"malformed ja4ts for {saddr}: {ja4ts!r}"
                )
        assert saw_synack, "no SYN-ACK responses observed; cannot validate ja4ts"
    finally:
        os.remove(OUTPUT)
