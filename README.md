s5proxy
===============
A SOCKS5 proxy server powered by libuv

# Features
- [x] Full implimentation without user name / password 
- [x] UDP associate supported.
- [x] Public IP deployment supported.

# How to build in ubuntu
```bash
sudo su                       # using root account
apt-get install --no-install-recommends build-essential autoconf libtool asciidoc xmlto -y
apt-get install git gcc g++ cmake automake -y
apt-get -f install -y
apt-get update -y
apt-get upgrade -y

git clone --recursive https://github.com/ssrlive/s5proxy.git
cd s5proxy
mkdir build && cd build
cmake .. && make
```

# Usage

```bash
s5proxy [-b <address>] [-d] [-h] [-t <timeout>] [-p <port>] [-u]

Options:

  -b <hostname|address>  Bind to this address or hostname.  Default: "0.0.0.0"
  -h                     Show this help message.
  -p <port>              Bind to this port number.  Default: 1080
  -t <timeout>           Idle timeout.  Default: 60
  -d                     Run in background as a daemon.
  -u                     This host has a public IP.

```
For example:  `./s5proxy -p 1080 -d`

