import sys
import os
import os.path

import sh
from sh import git, cd, make, rm, sudo, cp

def write_output(line):
	sys.stdout.write(line)

curl = sh.Command("curl")
tar = sh.Command("tar")

install_env = os.environ.copy()
install_env['CC'] = "gcc"

directory = os.path.dirname(os.path.realpath(__file__))

json_c_dir = os.path.join(directory, "json-c-json-c-0.12-20140410")
rm("-r", "-f", json_c_dir)

cd(directory)
tar(curl(
	"-L",
	"https://github.com/json-c/json-c/archive/json-c-0.12-20140410.tar.gz",
	_piped=True
), "-xz")

# Replace the Makefile.am.inc with one without -Werror
replacement_amfile = os.path.join(directory, "json_c_new_Makefile.am.inc")
original_amfile = os.path.join(json_c_dir, "Makefile.am.inc")
cp(replacement_amfile, original_amfile)

# Build it
cd(json_c_dir)
autogen_location = os.path.join(json_c_dir, "autogen.sh")
autogen = sh.Command(autogen_location)
autogen(prefix="/usr", _out=write_output, _env=install_env)
make(_out=write_output, _env=install_env)

if os.environ.get("ZMAP_TRAVIS_BUILD", None):
	print("Installing...")
	with sudo:
		make.install(_out=write_output, _env=install_env)

print("Done.")
