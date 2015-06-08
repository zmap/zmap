import sys
import os
import os.path

import sh
from sh import git, cd, make, rm, sudo, cp, chmod, mkdir

def write_output(line):
	sys.stdout.write(line)

curl = sh.Command("curl")
tar = sh.Command("tar")

install_env = os.environ.copy()
install_env['CC'] = "gcc"

directory = os.path.dirname(os.path.realpath(__file__))

# Download it
cd(directory)
curl(
	"-L",
	"http://www.cmake.org/files/v3.2/cmake-3.2.2-Linux-x86_64.sh",
	_out="cmake_installer.sh"
)

# Set up the installer
installer_path = os.path.join(directory, "cmake_installer.sh")
chmod("a+x", installer_path)
cmake_installer = sh.Command(installer_path)

# Verify the download
sum_str = sh.Command("openssl").sha1(installer_path)
expected_sum = "925e6185e94b717760453427b857fc4f2a4c2149"
if sum_str.split()[1] != expected_sum:
	raise Exception

# Install it
print("Installing...")
if os.environ.get("ZMAP_TRAVIS_BUILD", None):
	print("Travis CI build, installing to /opt")
	with sudo:
		cmake_installer(prefix="/opt", exclude_subdir=True)
else:
	prefix = os.path.join(directory, "cmake")
	mkdir(prefix)
	print("Installing to {}".format(prefix))
	cmake_installer(prefix=prefix, exclude_subdir=True)

print("Done.")
