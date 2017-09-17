CONTRIBUTING
============

ZMap accepts contributions in the form of issues and pull requests. In either
case, please search to see if it has been addressed previously before posting.

Developing
----------

- ZMap code follows the [Linux kernel style guide][kernelguide]. We mantain [a
  configuration file](/.clang-format) for `clang-format` that applies this
  style. You can use the [indent.sh](./indent.sh) script to apply this style.


Reviewing
---------

- All commits must be reviewed in the form of a pull request by a ZMap
  maintainer. This usually means @zakird or @dadrian (or both).

- All pull-requests should be squash-merged into master from the Github web
  interface. When in doubt, delete the commit messages from everything except
  the first commit. We don't need to see your development process, we just want a
  succint description of what this PR did in the Git log.

[kernelguide](https://www.kernel.org/doc/Documentation/process/coding-style.rst)

