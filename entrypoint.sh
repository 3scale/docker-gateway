#!/usr/local/bin/dumb-init /bin/sh
# 3scale (operations@3scale.net)
set -u

if [ "${AUTO_UPDATE_INTERVAL}" != 0 ] && [ "${AUTO_UPDATE_INTERVAL}" -lt 60 ]; then
  echo "AUTO_UPDATE_INTERVAL should be 60 or greater"
  exit 1
fi

pick_dns_server() {

  DNS=$(grep nameserver /etc/resolv.conf | awk {'print $2'})
  if [ -z "$DNS" ]; then
    echo "127.0.0.1"
  else
    for server in $DNS; do
      nslookup redhat.com "$server" &> /dev/null
      if [ $? -eq 0 ]; then
        echo "$server"
        break
      fi
    done
  fi


}

reload_openresty() {
  echo "Reloading Openresty"
  pkill -HUP -o nginx
}

download_threescale_config() {
  TEMP_DIR=$(mktemp -d)
  echo "Downloading threescale configuration, using endpoint: ${THREESCALE_ADMIN_URL}"
  curl  "${THREESCALE_ADMIN_URL}"/admin/api/nginx.zip?provider_key="${THREESCALE_PROVIDER_KEY}" -o "$TEMP_DIR"/nginx.zip
  cd "$TEMP_DIR" || exit
  unzip nginx.zip
  # Most docker PaaS doesn't allow docker to run as root
  # lets use the 8080 port instead of 80
  sed -E -i "s/listen\s+80;/listen 8080;/g" nginx_*.conf
  sed -E -i "s/resolver\s+8.8.8.8\s+8.8.4.4;/resolver ${RESOLVER};/g" nginx_*.conf
}

deploy_threescale_config() {
  echo "Deploying new configuration"
  cp -f "$TEMP_DIR"/nginx_*.conf /opt/openresty/nginx/conf/nginx.conf
  cp -f "$TEMP_DIR"/nginx_*.lua /opt/openresty/lualib/
  reload_openresty
}

compare_threescale_config() {

  download_threescale_config

  CURRENT_CONF_FILE=/opt/openresty/nginx/conf/nginx.conf
  NEW_CONF_FILE="$TEMP_DIR/nginx_*.conf"
  CURRENT_LUA_FILE="/opt/openresty/lualib/nginx_*.lua"
  NEW_LUA_FILE="$TEMP_DIR/nginx_*.lua"
  CHANGES=0

  diff -I "proxy_set_header  X-3scale-Version" $CURRENT_CONF_FILE $NEW_CONF_FILE
  if [ $? -eq 1 ]; then
    CHANGES=1
  fi

  diff -I "-- Generated.*--" $NEW_LUA_FILE $CURRENT_LUA_FILE
  if [ $? -eq 1 ]; then
    CHANGES=1
  fi

  if [ $CHANGES = 1 ]; then
    echo "Changes detected, deploying new configuration"
    deploy_threescale_config
    reload_openresty
  fi
}

export NAMESERVER

NAMESERVER=$(pick_dns_server)

export RESOLVER=${RESOLVER:-${NAMESERVER}}

sed -E -i "s/listen\s+80;/listen 8080;/g" /opt/openresty/nginx/conf/nginx.conf
nginx -g "daemon off;" &

download_threescale_config
deploy_threescale_config

trap 'download_threescale_config; deploy_threescale_config;' SIGUSR1
trap '' SIGHUP
trap '' SIGUSR2
trap '' WINCH

while true
do
  if [ "${AUTO_UPDATE_INTERVAL}" -ge 60 ]; then
    for _ in $(seq 1 "${AUTO_UPDATE_INTERVAL}"); do sleep 1; done
    compare_threescale_config
    rm -rf "$TEMP_DIR"
  else
    tail -f /dev/null & wait ${!}
  fi
done
