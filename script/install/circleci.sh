#!/bin/sh
set -x -e

apt-key adv --keyserver keyserver.ubuntu.com --recv-keys ECDCAD72428D7C01
apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C8CAB6595FDFF622

codename=$(lsb_release -sc)
tee /etc/apt/sources.list.d/ddebs.list << EOF
deb http://ddebs.ubuntu.com/ ${codename}      main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-security main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-updates  main restricted universe multiverse
deb http://ddebs.ubuntu.com/ ${codename}-proposed main restricted universe multiverse
EOF

wget -qO - https://openresty.org/package/pubkey.gpg | apt-key add -
add-apt-repository -y "deb http://openresty.org/package/ubuntu ${codename} main"
add-apt-repository -y ppa:niedbalski/systemtap-backports

apt update

echo manual > /etc/init/openresty.override

export OPENRESTY_VERSION="1.15.8.1-1~trusty1"

apt install -y cpanminus liblocal-lib-perl libev-dev luarocks python-pip systemtap libyaml-dev
apt install -y openresty=$OPENRESTY_VERSION openresty-debug=$OPENRESTY_VERSION openresty-opm=$OPENRESTY_VERSION openresty-resty=$OPENRESTY_VERSION openresty-debug-dbgsym=$OPENRESTY_VERSION openresty-openssl-debug-dbgsym openresty-pcre-dbgsym openresty-zlib-dbgsym

kernel=$(uname -r)
apt install -y "linux-headers-${kernel}" "linux-image-${kernel}-dbgsym"

# make ubuntu look more like RHEL
ln -s /usr/lib/x86_64-linux-gnu /usr/lib64

service openresty stop
