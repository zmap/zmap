#!/bin/bash
# PURPOSE  : lazy combined RHEL/CentOS/Fedora install including dependencies and setcap
# FILENAME : install.sh
# AUTHOR   : jczyz, 2015-12-11

# Ensure running as root/sudo
if [ "$EUID" -ne 0 ]; then 
    echo "Must be run as root or via sudo." >&2
    exit 1
fi

exit_if_failed () {
    ECODE=$?
    if [ $ECODE -ne 0 ]; then
        exit $ECODE
    fi;
}

if [[ "$OSTYPE" == "darwin"* ]]; then 
    OS="OSX"
    echo "This OS not yet supported by this script. Install manually."; exit 1
elif grep -q CentOS /etc/*-release; then 
    OS="CENTOS"
    yum -y install cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel
    exit_if_failed
elif grep -q AMI /etc/*-release; then 
    OS="AMI"
    echo "This OS not yet supported by this script. Install manually."; exit 1
elif grep -q Ubuntu /etc/*-release; then 
    OS="UBUNTU"
    echo "This OS not yet supported by this script. Install manually."; exit 1
elif grep -q Fedora /etc/*-release; then 
    OS="FEDORA"
    yum -y install cmake gmp-devel gengetopt libpcap-devel flex byacc json-c-devel libunistring-devel
    exit_if_failed
else
    OS="UNKNOWN"
    echo "This OS not yet supported by this script. Install manually."; exit 1
fi

cmake -DWITH_JSON=OFF -DENABLE_LOG_TRACE=OFF -DWITH_REDIS=OFF -DWITH_MONGO=OFF -DRESPECT_INSTALL_PREFIX_CONFIG=ON . && make -j4 && sudo make install \
&& \
setcap cap_net_raw=ep `which zmap` \
&& \
echo "Installed zmap version is: `zmap -V`" >&2

#EOF
