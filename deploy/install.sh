#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
config=
prefix=/
start=yes
while [ "$#" -gt 0 ]; do
    case "$1" in
        --config) [ "$#" -ge 2 ] || exit 2; config=$2; shift 2 ;;
        --prefix) [ "$#" -ge 2 ] || exit 2; prefix=$2; shift 2 ;;
        --no-start) start=no; shift ;;
        *) printf 'Usage: %s --config server.json [--no-start --prefix /staging]\n' "$0" >&2; exit 2 ;;
    esac
done
[ -n "$config" ] && [ -f "$config" ] || { printf 'A server configuration is required.\n' >&2; exit 2; }
case "$prefix" in /*) ;; *) printf 'Prefix must be absolute.\n' >&2; exit 2 ;; esac
case "$prefix" in *[!a-zA-Z0-9_./-]*|*/../*|*/..) printf 'Invalid prefix.\n' >&2; exit 2 ;; esac
mkdir -p -- "$prefix"
prefix=$(CDPATH= cd -P -- "$prefix" && pwd)
[ "$prefix" = / ] || [ "$start" = no ] || { printf 'A staging prefix requires --no-start.\n' >&2; exit 2; }
[ "$prefix" != / ] || [ "$(id -u)" -eq 0 ] || { printf 'Run the installer as root.\n' >&2; exit 2; }
for binary in quri quri-relay; do
    [ -x "$script_dir/$binary" ] || { printf 'Missing executable: %s\n' "$binary" >&2; exit 2; }
done
"$script_dir/quri-relay" -check-service -config "$config"

bin_dir=${prefix%/}/usr/local/bin
config_dir=${prefix%/}/etc/quri-relay
unit_dir=${prefix%/}/etc/systemd/system
state_dir=${prefix%/}/var/lib/quri-relay
[ ! -L "$config_dir" ] && [ ! -L "$config_dir/server.json" ] || { printf 'Refusing a symlinked configuration destination.\n' >&2; exit 1; }
if [ -f "$config_dir/server.json" ] && ! cmp -s "$config" "$config_dir/server.json"; then
    printf 'Existing server.json differs; update it explicitly before reinstalling.\n' >&2
    exit 1
fi
if [ "$prefix" = / ]; then
    command -v systemctl >/dev/null
    if ! id quri-relay >/dev/null 2>&1; then
        useradd --system --home-dir /var/lib/quri-relay --shell "$(command -v nologin)" quri-relay
    fi
fi
install -d -m 0755 "$bin_dir" "$unit_dir"
install -d -m 0700 "$config_dir" "$state_dir"
for binary in quri quri-relay; do
    temporary=$(mktemp "$bin_dir/.$binary.XXXXXX")
    install -m 0755 "$script_dir/$binary" "$temporary"
    mv -f -- "$temporary" "$bin_dir/$binary"
done
if [ ! -f "$config_dir/server.json" ]; then
    install -m 0600 "$config" "$config_dir/server.json"
fi
if [ "$prefix" = / ]; then
    chown root:quri-relay "$config_dir" "$config_dir/server.json"
    chmod 0750 "$config_dir"
    chmod 0640 "$config_dir/server.json"
    chown quri-relay:quri-relay "$state_dir"
    runuser -u quri-relay -- "$bin_dir/quri-relay" -check-service -config "$config_dir/server.json"
fi
temporary_unit=$(mktemp "$unit_dir/.quri-relay.XXXXXX")
cat > "$temporary_unit" <<EOF
[Unit]
Description=quri HTTP relay
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=quri-relay
Group=quri-relay
ExecStart=$bin_dir/quri-relay -config $config_dir/server.json
Restart=on-failure
RestartSec=3
StateDirectory=quri-relay
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=yes
ReadWritePaths=$state_dir
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
chmod 0644 "$temporary_unit"
mv -f -- "$temporary_unit" "$unit_dir/quri-relay.service"
if [ "$start" = yes ]; then
    systemctl daemon-reload
    systemctl enable --now quri-relay.service
    systemctl is-active --quiet quri-relay.service
fi
printf 'Installed quri-relay. Configuration: %s/server.json\n' "$config_dir"
