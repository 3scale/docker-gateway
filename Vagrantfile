# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Every Vagrant development environment requires a box. You can search for
  # boxes at https://atlas.hashicorp.com/search.
  config.vm.box = "centos/7"

  # Create a forwarded port mapping which allows access to a specific port
  # within the machine from a port on the host machine. In the example below,
  # accessing "localhost:8080" will access port 80 on the guest machine.
  # config.vm.network "forwarded_port", guest: 80, host: 8080

  # Create a private network, which allows host-only access to the machine
  # using a specific IP.
  # config.vm.network "private_network", ip: "192.168.33.10"

  # Create a public network, which generally matched to bridged network.
  # Bridged networks make the machine appear as another physical device on
  # your network.
  config.vm.network "private_network", type: 'dhcp'

  # Share an additional folder to the guest VM. The first argument is
  # the path on the host to the actual folder. The second argument is
  # the path on the guest to mount the folder. And the optional third
  # argument is a set of non-required options.
  # config.vm.synced_folder "../data", "/vagrant_data"

  # Provider-specific configuration so you can fine-tune various
  # backing providers for Vagrant. These expose provider-specific options.
  # Example for VirtualBox:
  #
   config.vm.provider "virtualbox" do |vb|
     vb.memory = "1024"
     vb.cpus = 2
   end

  # View the documentation for the provider you are using for more
  # information on available options.

  config.vm.synced_folder ".", "/home/vagrant/app"

  config.vm.provision "shell", inline: <<-SHELL
     # Install OpenResty and other tools
     yum-config-manager --add-repo https://openresty.org/yum/centos/OpenResty.repo
     yum -y install openresty-resty openresty-debuginfo openresty-pcre-debuginfo systemtap git epel-release httpd-tools
     yum -y install luarocks

     # Clone various utilities
     git clone https://github.com/openresty/stapxx.git /usr/local/stapxx || (cd /usr/local/stapxx && git pull)
     git clone https://github.com/brendangregg/FlameGraph.git /usr/local/flamegraph || (cd /usr/local/flamegraph && git pull)
     git clone https://github.com/openresty/openresty-systemtap-toolkit.git /usr/local/openresty-systemtap-toolkit || (cd /usr/local/openresty-systemtap-toolkit && git pull)
     curl -L https://github.com/tsenart/vegeta/releases/download/v6.1.1/vegeta-v6.1.1-linux-amd64.tar.gz | tar -xz --overwrite -C /usr/local/bin/

     # Utility to resolve builtin functions
     echo '#!/usr/bin/env luajit' > /usr/local/bin/ljff
     curl -L https://raw.githubusercontent.com/openresty/openresty-devel-utils/master/ljff.lua >> /usr/local/bin/ljff
     chmod +x /usr/local/bin/ljff

     # Create stap++ executable always pointing to its proper location
     echo '#!/bin/sh' > /usr/local/bin/stap++
     echo 'exec /usr/local/stapxx/stap++ -I /usr/local/stapxx/tapset "$@"' >> /usr/local/bin/stap++
     chmod +x /usr/local/bin/stap++

     # Install APIcast dependencies
     luarocks make app/apicast/*.rockspec --tree /usr/local/openresty/luajit

     # Add various utilites to the PATH
     ln -sf /usr/local/openresty/luajit/bin/luajit /usr/local/bin/luajit
     ln -sf /usr/local/flamegraph/*.pl /usr/local/bin/
     ln -sf /usr/local/stapxx/samples/*.sxx /usr/local/bin/
     ln -sf /usr/local/openresty-systemtap-toolkit/fix-lua-bt /usr/local/bin/
     ln -sf /usr/local/openresty-systemtap-toolkit/ngx-pcre* /usr/local/bin/

     # Allow vagrant user to use systemtap
     usermod -a -G stapusr,stapdev vagrant

     # Raise opened files limit for vagrant user
     echo -e 'vagrant\t\t\t-\tnofile\t\t1000000' > /etc/security/limits.d/90-nofile.conf
  SHELL
end
