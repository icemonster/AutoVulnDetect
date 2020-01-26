#!/bin/sh

sudo apt install python python3 python3-pip

wget https://github.com/BinaryAnalysisPlatform/bap/releases/download/v1.6.0/{bap,libbap,libbap-dev}_1.6.0.deb
sudo dpkg -i {bap,libbap,libbap-dev}_1.6.0.deb

sudo apt install python3-dev git
pip3 install --upgrade git+https://github.com/arthaud/python3-pwntools.git --user
sudo apt install python-pip

sudo apt-get install openssl
sudo apt-get install libssl-dev
sudo apt install gdb

pip3 install --no-binary keystone-engine keystone-engine --user
pip3 install cle --user #otherwise, git clone it and execute "pip3 install ." on the folder

sudo apt-get install gcc-multilib

pip3 install z3-solver --user
pip3 install sympy bap avatar2 --user
