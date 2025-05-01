# Building ZMap for various Package Managers

## Debian/Ubuntu

1. Enviornment
You'll need to take these steps from an Ubuntu/Debian VM and you'll need a GPG signing key. I'd recommend a local Ubuntu VM with local GPG key, I couldn't figure out how to setup USB passthrough for a Yubikey into a UTM VM.

Ensure GPG is working correctly:
```shell
echo "test" | gpg --clearsign
```

Add the following to your `.bashrc` or `.zshrc` file:
```shell
export DEBEMAIL="phillip@cs.stanford.edu"
export DEBFULLNAME="Phillip Stephens"
```

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
- changelog - add a new version. This is mandatory so the scripts know the version they're building for. `dch -i` should open a text editor to set things like date and version automatically.

If a new depedency has been added, you'll need to modify `debian/control`

1. Build
From inside `/tmp/zmap-build/zmap-X.Y.Z/`, run:
```shell
debuild -S -sa -us -uc
debsign ../zmap_X.Y.Z-W_source.changes
```

1. Check for Lint Errors
```shell
cd ../ # Move to directory above
lintian zmap_X.Y.Z-1_source.changes
```

1. Test that the release is build correctly
Build a binary:
From inside the `zmap-X.Y.Z` folder:
```shell
debuild -b -us -uc
cd ../
sudo docker run --rm -it -v $PWD:/mnt ubuntu:24.04 bash
```
Once inside the docker container we'll update the packages and then check if we can install ZMap from the *.deb file and check the version. Version is set within `CMakeLists.txt`
```shell
apt update
apt install -f /mnt/zmap_4.3.3-2_arm64.deb
zmap --version
```


1. If no errors, upload
```shell
dput mentors zmap_X.Y.Z-1_source.changes
```

> [!NOTE]
> It may take a few minutes to appear, but visit https://mentors.debian.net/package/zmap/ and you should see it. You'll also get an email when it arrives.

1. Test the 
