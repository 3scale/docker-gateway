#!/bin/sh -x

PREFIX=${1:-$HOME/bin}
sha1=44c9783901aa92ae9c7e02f68eb3d617c07c95a7

if [ ! -f "${PREFIX}/stapxx" ]; then
  mkdir -p "${PREFIX}"
  wget -T 60 -c "https://github.com/openresty/stapxx/archive/${sha1}.tar.gz" -O /tmp/stapxx.tar.gz

  tar -xzf /tmp/stapxx.tar.gz -C /tmp
  mv -v "/tmp/stapxx-${sha1}/samples"/* "${PREFIX}"
  mv -v "/tmp/stapxx-${sha1}/stap++" "${PREFIX}"
  rm -rf /tmp/stapxx**
else
  echo "Using cached stap++."
fi
