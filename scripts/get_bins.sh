#!/usr/bin/env bash
# Скачивает Xray-core и sing-box в bin/.
# Устойчив к transient-сбоям GitHub (504 и т.п.): ретраи curl + отказ одного
# движка не роняет проверку целиком (run#14 упал именно на 504). Полный
# провал (ни одного бинарника) = ошибка — без движков deep-тест бессмыслен.
set -uo pipefail
cd "$(dirname "$0")/.."
mkdir -p bin

try() { curl -fsSL --retry 5 --retry-delay 10 --retry-all-errors "$@"; }

# --- Xray-core (vless / vmess / trojan / shadowsocks) ---
if [ ! -x bin/xray ]; then
  echo "[*] Скачиваю Xray-core..."
  rm -rf /tmp/xray_ex && mkdir -p /tmp/xray_ex
  if try -o /tmp/xray.zip \
       "https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip" \
     && python3 -m zipfile -e /tmp/xray.zip /tmp/xray_ex \
     && mv /tmp/xray_ex/xray bin/xray && chmod +x bin/xray; then
    echo "[ok] Xray-core скачан"
  else
    echo "[!] Xray-core не скачался — vless/vmess/trojan/ss пойдут только по порту"
  fi
fi

# --- sing-box (hysteria2 / tuic / anytls) ---
if [ ! -x bin/sing-box ]; then
  echo "[*] Скачиваю sing-box..."
  # последняя версия — по redirect страницы releases/latest (без GitHub API,
  # чтобы не ловить rate limit)
  TAG=""
  TAG=$(try -o /dev/null -w '%{url_effective}' 2>/dev/null \
        "https://github.com/SagerNet/sing-box/releases/latest") || TAG=""
  TAG=${TAG##*/}
  if [ -n "$TAG" ]; then
    rm -rf /tmp/sb_ex && mkdir -p /tmp/sb_ex
    if try -o /tmp/singbox.tar.gz \
         "https://github.com/SagerNet/sing-box/releases/download/${TAG}/sing-box-${TAG#v}-linux-amd64.tar.gz" \
       && tar -xzf /tmp/singbox.tar.gz -C /tmp/sb_ex \
       && mv /tmp/sb_ex/sing-box-*/sing-box bin/sing-box && chmod +x bin/sing-box; then
      echo "[ok] sing-box скачан"
    else
      echo "[!] sing-box не скачался — hysteria2/tuic/anytls пойдут только по порту"
    fi
  else
    echo "[!] Не удалось определить версию sing-box (страница releases недоступна)"
  fi
fi

# итог: без обоих движков deep-тест деградирует до «только порт» —
# это хуже, чем честно упасть и оставить старую (проверенную) подписку
if [ ! -x bin/xray ] && [ ! -x bin/sing-box ]; then
  echo "::error::Не скачался ни один движок проверки (Xray-core и sing-box)"
  exit 1
fi

[ -x bin/xray ] && echo "[ok] $(bin/xray version | head -n1)"
[ -x bin/sing-box ] && echo "[ok] $(bin/sing-box version | head -n1)"
exit 0
