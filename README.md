s5proxy
===============
A SOCKS5 proxy powered by libuv

# How to build in ubuntu
```bash
sudo su                       # using root account
apt-get install --no-install-recommends build-essential autoconf libtool asciidoc xmlto -y
apt-get install git gcc g++ cmake automake -y
apt-get -f install
apt-get update
apt-get upgrade

git clone https://github.com/ssrlive/s5proxy.git
cd s5proxy
git submodule update --init
cmake . && make
```
