ZMap uses a **full-disclosure only** security policy.

ZMap is a memory-unsafe program that contacts every host on the Internet. We
recommend Internet-wide scans be ran on untrusted scanning hosts. Our security
policy reflects this, and as such, ZMap does not partake in coordinated
disclosure, nor do we issue CVEs for ZMap. We also do not backport patches.

ZMap does _not_ accept security reports over any private channel, including the
Github vulnerability reporting mechanisms.

If you find a security vulnerability in ZMap, and you would like credit for it
from maintainers, you have two options:
- **Submit a PR**: The most concise way to explain most issues in ZMap (e.g. a
  malformed bounds check) is to submit a PR. Particularly with LLMs, we would
  rather read a two line PR than four paragraphs and a "POC". You will be
  credited when we merge the PR.
- **File an Issue**: Filing a PR is likely more concise and easier for everyone.
  However, if the change is not immediately obvious or is otherwise out of reach
  of coding agents, you can file an issue. If the bug is fixed, your issue will be
  credited in the commit. All ZMap issues are public.

If you send us an issue privately, and we do patch it, you _will not be
credited_, particularly if you send us an order of magnitude more text than the
PR would have been to fix it.

We are happy to respond to well-formed **public** issues and PRs.
