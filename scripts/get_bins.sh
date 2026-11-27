#!/usr/bin/env bash
# Скачивает Xray-core и sing-box в bin/ (один раз, кэшируется между запусками не хранится).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin

# --- Xray-core (проверка vless / vmess / trojan / shadowsocks) ---
if [ ! -x bin/xray ]; then
  echo "[*] Скачиваю Xray-core..."
  curl -fsSL --retry 3 -o /tmp/xray.zip \
    "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip"
  rm -rf /tmp/xray_ex && mkdir -p /tmp/xray_ex
  python3 -m zipfile -e /tmp/xray.zip /tmp/xray_ex
  mv /tmp/xray_ex/xray bin/xray
  chmod +x bin/xray
fi

# --- sing-box (проверка hysteria2 / tuic / anytls) ---
if [ ! -x bin/sing-box ]; then
  echo "[*] Скачиваю sing-box..."
  # последняя версия — по redirect страницы releases/latest (без GitHub API, чтобы не ловить rate limit)
  TAG=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
    "https://github.com/SagerNet/sing-box/releases/latest")
  VER=${TAG##*/}   # например v1.14.4
  curl -fsSL --retry 3 -o /tmp/singbox.tar.gz \
    "https://github.com/SagerNet/sing-box/releases/download/${VER}/sing-box-${VER#v}-linux-amd64.tar.gz"
  rm -rf /tmp/sb_ex && mkdir -p /tmp/sb_ex
  tar -xzf /tmp/singbox.tar.gz -C /tmp/sb_ex
  mv /tmp/sb_ex/sing-box-*/sing-box bin/sing-box
  chmod +x bin/sing-box
fi

echo "[ok] $(bin/xray version | head -n1)"
echo "[ok] $(bin/sing-box version | head -n1)"
