#!/bin/bash
#
# installation script for AutoVulnDetect
# supports? Debian-based (apt) and RHEL (yum) systems
# navigation warnings:
#   posix-ipc only compiles under gcc
#   cle may not compile, in which case run commented pip3 + git command
#

OS=$(grep "^NAME=" /etc/os-release | cut -d= -f2)

if [[ ${OS} = "\"Ubuntu\"" || ${OS} = "Debian" ]]
then
    echo "Installing on apt system"
    sudo apt install gcc-multilib gdb git libssl-dev openssl python python3 python3-pip python3-dev wget
    #wget https://github.com/BinaryAnalysisPlatform/bap/releases/download/v2.0.0/{bap,libbap,libbap-dev}_2.0.0.deb
    #sudo dpkg -i {bap,libbap,libbap-dev}_2.0.0.deb
    #rm *.deb
elif [[ ${OS} = "Fedora" || ${OS} = "CentOS" || ${OS} = "RedHat" ]]
then
    echo "Installing on RHEL system"
    sudo yum install gdb gdb-gdbserver git glibc-devel.i686 openssl openssl-devel openssl-libs python python3 python3-pip python3-devel wget
    wget https://github.com/BinaryAnalysisPlatform/bap/releases/download/v2.0.0/{bap,libbap,libbap-dev}-2.0.0-2.x86_64.rpm
    sudo rpm -i {bap,libbap,libbap-dev}-2.0.0-2.x86_64.rpm
    rm *.rpm
else
    echo "System ${OS} not supported yet"
    exit 1
fi

CC=gcc pip3 install posix-ipc --user
pip3 install --no-binary keystone-engine keystone-engine --user
pip3 install --upgrade git+https://github.com/Gallopsled/pwntools --user
pip3 install avatar2 bap cle z3-solver --user
#pip3 install --upgrade git+https://github.com/angr/cle.git --user
