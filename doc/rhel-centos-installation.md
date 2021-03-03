# APIcast v3 installation on RHEL/CentOS

This document explains how to install and run [APIcast v3](https://github.com/3scale/apicast/releases/latest) on a clean RHEL/CentOS. 

Below you can find an example of how to install APIcast v3.2.0 (a component of 3scale API Management v2.2) natively on Red Hat Enterprise Linux/CentOS, the following steps need to be performed (tested on RHEL v7.5/CentOS v7.5.1804 (Core)):

## Install OpenResty and dependencies

1) Switch to root
```shell
sudo -i
```

2) Install dependencies
```shell
yum install -y yum-utils gcc git
```

3) Enable OpenResty repo (see RHEL section at https://openresty.org/en/linux-packages.html)
```shell
yum-config-manager --add-repo https://openresty.org/package/rhel/openresty.repo
```

4) Enable EPEL packages (needed for LuaRocks)
```shell
yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
```

5) Upgrade yum
```shell
yum upgrade -y
```

6) Install OpenResty (see RHEL section at https://openresty.org/en/linux-packages.html)
```shell
yum install -y openresty-openssl-1.0.2k
export OPENRESTY_RPM_VERSION="1.13.6.1"
yum install -y \
     openresty-${OPENRESTY_RPM_VERSION} \
     openresty-resty-${OPENRESTY_RPM_VERSION}
```

7) Install LuaRocks
```shell
export LUAROCKS_VERSION="2.3.0"
yum install -y luarocks-${LUAROCKS_VERSION}
```

8) Configure Lua environment
```shell
mkdir -p /usr/share/lua/5.1/luarocks/

cat << EOF > /usr/share/lua/5.1/luarocks/site_config.lua
local site_config = { }

local openresty = [[/usr/local/openresty]]
local luajit = openresty .. [[/luajit]]

site_config.LUAROCKS_SYSCONFIG=openresty .. [[/config-5.1.lua]]
site_config.LUA_INTERPRETER=[[resty]]
site_config.LUA_DIR_SET=false
site_config.LUAROCKS_PREFIX= [[/usr]]
site_config.LUA_INCDIR= luajit .. [[/include/luajit-2.1]]
site_config.LUA_LIBDIR= luajit .. [[/lib/5.1]]
site_config.LUA_BINDIR= openresty .. [[/bin]]
site_config.LUAROCKS_SYSCONFDIR=[[/etc/luarocks]]
site_config.LUAROCKS_ROCKS_TREE=[[/usr/local/openresty/luajit]]
site_config.LUAROCKS_ROCKS_SUBDIR=[[/luarocks/rocks]]
site_config.LUAROCKS_UNAME_S=[[Linux]]
site_config.LUAROCKS_UNAME_M=[[x86_64]]
site_config.LUAROCKS_DOWNLOADER=[[curl]]
site_config.LUAROCKS_MD5CHECKER=[[md5sum]]

site_config.LUAROCKS_EXTERNAL_DEPS_SUBDIRS={ bin="bin", lib={ "lib", [[lib64]] }, include="include" }
site_config.LUAROCKS_RUNTIME_EXTERNAL_DEPS_SUBDIRS={ bin="bin", lib={ "lib", [[lib64]] }, include="include" }

return site_config
EOF
```

9) Return to non-root user
```shell
exit
```

## Install APIcast v3

To use the latest APIcast version, you can check out the latest release in the [APIcast GitHub repository](https://github.com/3scale/apicast/releases/latest).

If you want to use a specific version of APIcast, check the APIcast [releases page](https://github.com/3scale/apicast/releases). You can either download the source code from there, or checkout a specific tag with `git`, for example:

1) Download the v3.2.0 release (Red Hat 3scale API Management v2.2) and extract it.
```shell
curl -L -o apicast-3.2.0.tar.gz https://github.com/3scale/apicast/archive/v3.2.0.tar.gz
tar xzvf apicast-3.2.0.tar.gz
cd apicast-3.2.0
```

2) Install the dependencies
```shell
make dependencies
```

## Run APIcast v3 on OpenResty

```shell
THREESCALE_PORTAL_ENDPOINT=https://{ACCESS_TOKEN}@{DOMAIN}-admin.3scale.net \
THREESCALE_DEPLOYMENT_ENV=staging \
APICAST_CONFIGURATION_LOADER=lazy \
APICAST_CONFIGURATION_CACHE=0 \
bin/apicast -vvv
```

This command will start APIcast v3 and download the latest API gateway configuration from the 3scale admin portal.

`bin/apicast` executable accepts a number of options, you can check them out by running:

```shell
bin/apicast -h
```

Additional parameters can be specified using environment variables.

Example:
```shell
APICAST_LOG_FILE=logs/error.log bin/apicast -c config.json -d -v -v -v
```

The above command will load the APIcast using the configuration file `config.json`, will run as daemon (`-d` option), and the error log will be at `debug` level (`-v -v -v`) and will be written to the file `logs/error.log` inside the directory `apicast` (the *prefix* directory).


## Common Issues

**During make dependencies step:**
```shell
ERROR: lua_modules/share/lua/5.1/rover/install.lua:44: Build error: Failed compiling object src/lfs.o
```
Make sure you install "Development Tools" package

**Missing dependencies:**
```shell
ERROR: ...user/apicast-3.2.0/lua_modules/share/lua/5.1/pl/path.lua:28: pl.path requires LuaFileSystem
stack traceback:
...user/apicast-3.2.0/lua_modules/share/lua/5.1/pl/path.lua:28: in main chunk
[C]: in function 'require'
...ser/apicast-3.2.0/gateway/src/apicast/cli/filesystem.lua:6: in main chunk
[C]: in function 'require'
...-user/apicast-3.2.0/gateway/src/apicast/cli/template.lua:11: in main chunk
[C]: in function 'require'
.../apicast-3.2.0/gateway/src/apicast/cli/command/start.lua:15: in main chunk
[C]: in function 'require'
/home/ec2-user/apicast-3.2.0/gateway/src/apicast/cli.lua:18: in function 'load_commands'
/home/ec2-user/apicast-3.2.0/gateway/src/apicast/cli.lua:23: in main chunk
[C]: in function 'require'
/tmp/JjRZz6pdQp:60: in function 'file_gen'
init_worker_by_lua:48: in function <init_worker_by_lua:46>
[C]: in function 'xpcall'
init_worker_by_lua:55: in function <init_worker_by_lua:53>
```

From within the /home/ec2-user/apicast-3.x.x directory try the following:
```shell
rm -rf lua_modules
make dependencies
```
