# Threat model

## What this project does and where untrusted input enters
- ZMap is a stateless network scanner. It sends probes, usually a single packet, to large address ranges and parses whatever comes back.
- The main untrusted input is packets received from the network. Any host on the Internet can send ZMap arbitrary responses, so the receive path (`src/recv*.c`), the probe modules' response validation and parsing (`src/probe_modules/`), and the output modules that serialize parsed fields (`src/output_modules/`) are the attack surface.
- Command-line arguments, config files, allowlists/blocklists, and output filter expressions (`src/lexer.l`, `src/parser.y`, `src/filter.c`) come from the operator and are trusted.
- Memory leaks are not considered security issues.

## Components that matter most / least
- Most important: packet parsing in `src/probe_modules/` (primarily TCP)  and `src/probe_modules/packet.c`, along with `src/recv.c` and `src/validate.c`.
- Less important: the target iterator, sharding, and blocklist code in `lib/` and `src/`. These only see operator input.
- Out of scope: PF_RING and netmap send/receive paths. They are not built by default. Blocklist issues are not security vulnerabilities. Issues only in ziterate and zblocklist are not security vulnerabilities.

## How to exercise it
- The `zmap`, `ziterate`, and `zblocklist` binaries are in `/src/build/src/`.
- `test/unit/` builds a standalone test for the JA4TS formatter.
- `test/integration-tests/` contains pytest tests. Most of them need a live network. `--dryrun` mode works offline.

## How you rate severity
- A memory-safety bug that a remote host can trigger by sending response packets is high for TCP and medium for any other probe module.
- A remote crash or hang of the scanner is low.
- Bugs that only the local operator can trigger through flags, config, or filter expressions are not bugs.

## Anything to leave alone
- Do not report that ZMap needs raw-socket privileges or that it sends traffic to the targets it was configured to scan. Both are by design.
- Issues with privsep are also not relevant, in general the scanning box should be untrusted and for scanning only.
