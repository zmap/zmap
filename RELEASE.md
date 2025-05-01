# Building ZMap for various Package Managers

## Debian/Ubuntu

1. Enviornment
You'll need to take these steps from an Ubuntu/Debian VM.

1. Install deps

```shell
sudo apt install devscripts build-essential debhelper dh-make
```

In order for the debian scripts to find what they need, it's important to follow these steps exactly so the directory structure matches.

1. Clone ZMap into a versioned directory and create `orig` tarball
The debian build pipeline requires this step.
```shell
mkdir /tmp/zmap-build
git clone git@github.com:zmap/zmap.git /tmp/zmap-build/zmap-X.Y.Z    # set the version appropriately
cd /tmp/zmap-build
tar --exclude=debian -czf zmap_X.Y.Z.orig.tar.gz zmap-X.Y.Z
cd zmap-X.Y.Z
```

1. Modify necessary files
At a minimum, you'll need to modify in the `debian/` directory:
- changelog - add a new version. This is mandatory so the scripts know the version they're building for.

If a new depedency has been added, you'll need to modify `debian/control`

1. Build
From inside `/tmp/zmap-build/zmap-X.Y.Z/`, run:
```shell
debuild -us -uc
```
