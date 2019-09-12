#!/bin/sh
set -eux

PREFIX=${1:-$HOME/bin}

os=$(uname -s | tr '[:upper:]' '[:lower:]')
arch=$(uname -m | sed 's/x86_/amd/' | tr -d 'i' | sed 's/686/386/')
version=$(echo "${S2I_VERSION}" | cut -f1 -d-)
sha=$(echo "${S2I_VERSION}" | cut -f2 -d-)

install_s2i(){
  cd /tmp/
  mkdir -p "${PREFIX}"
  wget -T 60 -c "https://github.com/openshift/source-to-image/releases/download/v${version}/source-to-image-v${version}-${sha}-${os}-${arch}.tar.gz" -O source-to-image.tar.gz
  tar -xzf source-to-image.tar.gz -C "${PREFIX}/"
  rm -rf source-to-image.tar.gz
}

if [ ! -f "${PREFIX}/s2i" ]; then
    echo "Installing s2i"
    install_s2i
    exit 0
fi

installed_version=$(s2i version | awk '{print substr($2,2)}')


if [ "$installed_version" != "$version" ]; then
    echo "Installing s2i because mismatched version current_version='$installed_version'"
    # Installed a new version because it's not the same
    install_s2i
fi

# Using installed version
