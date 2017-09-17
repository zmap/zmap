CONTRIBUTING
============

ZMap accepts contributions in the form of issues and pull requests. In either
case, please search to see if it has been addressed previously before posting.

Developing
----------

- ZMap code follows the [Linux kernel style guide][kernelguide]. We mantain [a
  configuration file](/.clang-format) for `clang-format` that applies this
  style. You can use the [indent.sh](./indent.sh) script to apply this style.

- Before submitting a PR, please rebase/squash your commits down to a single
  commit. Follow these [commit message guidelines][guidelines], especially with
  regard to formatting.


Reviewing
---------

- All commits must be reviewed in the form of a pull request by a ZMap
  maintainer. This usually means @zakird or @dadrian (or both).

- All pull-requests should be squash-merged into master.

- When squash-merging, put the PR number in the commit title. Github does this
  automatically in the web interface.  Condense the commit messages down to a
  single messsage; often this can just be the commit message from the first
  commit in a PR. Follow the commit formatting guidelines [here][guidelines].

[kernelguide]: https://www.kernel.org/doc/Documentation/process/coding-style.rst
[guidelines]: https://github.com/torvalds/subsurface-for-dirk/blob/master/README#L92
