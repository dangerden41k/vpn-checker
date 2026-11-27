#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VPN Checker (DangerVPN) — проверялка серверов из публичных подписок.

Как работает:
 1. Скачивает источники из sources.txt (обычный текст или base64).
 2. Парсит ссылки: vless, vmess, trojan, ss, ssr, hysteria2, tuic, anytls, socks/http.
 3. Дедуплицирует (одинаковый сервер в разных списках остаётся один раз).
 4. Этап 1 — TCP-проверка host:port (быстро отсекает мёртвые).
 5. Этап 2 (--deep) — реальный тест: поднимает Xray-core или sing-box с
    тестируемым сервером и качает через него тестовую страницу.
 6. Классифицирует серверы на две категории:
      «Белый» — сервер прячется за доменом/CDN (Cloudflare и т.п.) и/или
      использует нестандартный UDP-протокол (hysteria2/tuic) — теоретически
      способен работать в режиме «белых списков» (когда обычный интернет
      заблокирован, а разрешены только отдельные адреса);
      «ЧС» (чёрный список) — обычные TCP-серверы на «серых» IP без домена:
      работают, когда интернет не заблокирован (обычные Wi-Fi/LTE).
 7. Определяет страну и город каждого живого сервера через ipwho.is (API
    сервиса ipwhois.io, без ключа, с кешем на 14 дней в ip_cache.json).
 8. Пишет подписки с простыми именами «🇬🇧 Британия — Лондон» (флаг +
    страна — город; протокол, бренд и счёт не пишем — клиент показывает
    протокол сам), первой строкой — псевдо-сервер с пометкой об
    автообновлении каждые 6 часов:
    sub_plain.txt + sub_base64.txt (всё вместе),
    white_plain.txt + white_base64.txt (только «Белый»),
    black_plain.txt + black_base64.txt (только «ЧС»),
    а также обновляет блок статистики в README.md.

Зависимости: только стандартная библиотека Python 3.8+.
"""

import argparse
import base64
import gzip
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import parse_qs, unquote, urlparse

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 vpn-checker/1.0"

# голый IPv4 / IPv6-адрес?
HOST_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$|^[0-9a-fA-F:]+$")

LINK_RE = re.compile(
    r"^(vless|vmess|trojan|ss|ssr|hysteria2|hy2|hysteria|tuic|anytls|"
    r"socks5?|https?|wireguard|naive|snell|mieru)://", re.I)

# Тестовые цели (HTTP, чтобы не зависеть от TLS): (host, port, path)
TEST_URLS = [
    ("connectivitycheck.gstatic.com", 80, "/generate_204"),
    ("cp.cloudflare.com", 80, "/generate_204"),
    ("www.gstatic.com", 80, "/generate_204"),
]

STATS_START = "<!-- STATS:START -->"
STATS_END = "<!-- STATS:END -->"

# ---------------------------------------------------------------------------
# Имя подписки и категории.
#
# «Белый» (работает, когда интернет заблокирован / режим белых списков):
#   - адрес сервера — домен, а не голый IP: в периметре ТСПУ/DPI выживает
#     только трафик к «разрешённым» адресам, и единственный реальный шанс —
#     когда VPN спрятан за доменом из CDN (Cloudflare и т.п.) или за доменом
#     крупного сервиса, который не могут вырезать из белого списка целиком;
#   - и/или протокол на UDP с нестандартным поведением (hysteria2/tuic):
#     их сигнатуры DPI пока распознаёт хуже классического TLS-over-TCP.
#   Гарантии нет — белые списки у каждого оператора свои, это лишь
#   «претенденты»: нужно пробовать на месте.
# «ЧС» (чёрный список; работает при обычном Wi-Fi/LTE, когда интернет НЕ
#   заблокирован): обычные TCP-серверы на голых IP — при включении белых
#   списков такой трафик до сервера просто не дойдёт.
# ---------------------------------------------------------------------------

BRAND = "DangerVPN"

# домены, под которыми чаще всего прячут CDN-fronted серверы
CDN_DOMAIN_RE = re.compile(
    r"\.(cloudflare|cdnflare|cf\.\w+|trycloudflare|jsdelivr|fastly|"
    r"cloudfront|azureedge|akamai|gc\.googleusercontent|workers\.dev|"
    r"pages\.dev|vercel\.app|netlify\.app|herokuapp\.com|"
    r"ddns\.net|duckdns\.org|no-ip\.org|hopto\.org|zapto\.org|"
    r"serveminecraft\.biz|sytes\.net|myftp\.org|myftp\.biz|"
    r"dynu\.com|dynu\.net|freedns\.afraid\.org"
    r")($|\.)", re.I)

# протоколы поверх UDP — DPI в режиме белых списков их пока вырезает хуже
UDP_PROTOS = {"hysteria2", "tuic"}


def domain_root(host):
    """'a.b.example.com' -> 'example.com' (грубая эвристика для 2-3 уровней)."""
    if not host or HOST_IP_RE.match(host):
        return None
    # вырезаем порт, если вдруг прилетел
    host = host.split(":")[0].strip("[]")
    parts = host.strip(".").split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3:  # co.uk, com.ru и т.п.
        return ".".join(parts[-3:])
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def classify(srv):
    """'white' | 'black' — категория сервера (см. комментарий выше)."""
    host = srv["host"]
    if host and not HOST_IP_RE.match(host):
        root = domain_root(host) or ""
        # домен за CDN / динамическим DNS — главный кандидат в «Белый»
        if CDN_DOMAIN_RE.search(root) or CDN_DOMAIN_RE.search(host):
            return "white"
        # любой другой домен: DNS-имя может указывать в CDN или на
        # «неудобный для блокировки» адрес — оставляем в «Белом»
        return "white"
    # hysteria2/tuic на голом IP всё равно заносим в «Белый»: UDP+обфускация
    if srv["proto"].lower() in UDP_PROTOS:
        return "white"
    return "black"


# ---------------------------------------------------------------------------
# Геолокация IP (ipwho.is — открытый API сервиса ipwhois.io, без ключа).
# Результаты кешируются в ip_cache.json: у API лимит ~10k запросов/мес,
# а проверка ходит каждые 6 часов. Свежими считаем записи младше 14 дней.
# ---------------------------------------------------------------------------

GEO_API = "https://ipwho.is/{ip}"
GEO_CACHE = "ip_cache.json"
GEO_MAX_AGE_DAYS = 14

# Русские названия стран по ISO-коду (что не найдём — оставим английское из API)
COUNTRY_RU = {
    "AU": "Австралия", "AT": "Австрия", "AZ": "Азербайджан", "AL": "Албания",
    "DZ": "Алжир", "AR": "Аргентина", "AM": "Армения", "BS": "Багамы",
    "BD": "Бангладеш", "BY": "Беларусь", "BE": "Бельгия", "BG": "Болгария",
    "BA": "Босния и Герцеговина", "BR": "Бразилия", "GB": "Британия",
    "HU": "Венгрия", "VE": "Венесуэла", "VN": "Вьетнам", "GA": "Габон",
    "GE": "Грузия", "DE": "Германия", "HK": "Гонконг", "GR": "Греция",
    "DK": "Дания", "DO": "Доминикана", "EG": "Египет", "IL": "Израиль",
    "IN": "Индия", "ID": "Индонезия", "JO": "Иордания", "IQ": "Ирак",
    "IR": "Иран", "IE": "Ирландия", "IS": "Исландия", "ES": "Испания",
    "IT": "Италия", "KZ": "Казахстан", "KH": "Камбоджа", "CA": "Канада",
    "QA": "Катар", "CY": "Кипр", "KG": "Кыргызстан", "CN": "Китай",
    "CO": "Колумбия", "CR": "Коста-Рика", "XK": "Косово", "KW": "Кувейт",
    "LV": "Латвия", "LT": "Литва", "LI": "Лихтенштейн", "LU": "Люксембург",
    "MY": "Малайзия", "MT": "Мальта", "MA": "Марокко", "MX": "Мексика",
    "MD": "Молдова", "MN": "Монголия", "AE": "ОАЭ", "NZ": "Новая Зеландия",
    "NO": "Норвегия", "PA": "Панама", "PY": "Парагвай", "NL": "Нидерланды",
    "NP": "Непал", "NG": "Нигерия", "PK": "Пакистан", "PE": "Перу",
    "PL": "Польша", "PT": "Португалия", "RU": "Россия", "RO": "Румыния",
    "SA": "Саудовская Аравия", "MK": "Северная Македония", "SG": "Сингапур",
    "SI": "Словения", "SK": "Словакия", "US": "США", "TH": "Таиланд",
    "TZ": "Танзания", "TN": "Тунис", "TM": "Туркменистан", "TR": "Турция",
    "UG": "Уганда", "UZ": "Узбекистан", "UA": "Украина", "PH": "Филиппины",
    "FI": "Финляндия", "FR": "Франция", "HR": "Хорватия", "ME": "Черногория",
    "CZ": "Чехия", "CL": "Чили", "CH": "Швейцария", "SE": "Швеция",
    "LK": "Шри-Ланка", "EE": "Эстония", "ET": "Эфиопия", "ZA": "ЮАР",
    "KR": "Южная Корея", "JM": "Ямайка", "JP": "Япония",
}

# Города по английскому написанию (как отдаёт ipwhois). Чего нет в словаре —
# останется по-английски, это не страшно.
CITY_RU = {
    # Россия
    "Moscow": "Москва", "Saint Petersburg": "Санкт-Петербург",
    "St Petersburg": "Санкт-Петербург", "Novosibirsk": "Новосибирск",
    "Yekaterinburg": "Екатеринбург", "Kazan": "Казань",
    "Nizhny Novgorod": "Нижний Новгород", "Chelyabinsk": "Челябинск",
    "Samara": "Самара", "Omsk": "Омск", "Rostov-on-Don": "Ростов-на-Дону",
    "Krasnodar": "Краснодар", "Voronezh": "Воронеж", "Perm": "Пермь",
    "Volgograd": "Волгоград", "Saratov": "Саратов", "Tyumen": "Тюмень",
    "Ufa": "Уфа", "Irkutsk": "Иркутск", "Khabarovsk": "Хабаровск",
    "Vladivostok": "Владивосток", "Tolyatti": "Тольятти",
    "Izhevsk": "Ижевск", "Barnaul": "Барнаул", "Kemerovo": "Кемерово",
    "Ryazan": "Рязань", "Penza": "Пенза", "Lipetsk": "Липецк",
    "Tula": "Тула", "Kirov": "Киров", "Cheboksary": "Чебоксары",
    "Khimki": "Химки", "Krasnoturinsk": "Краснотурьинск",
    "Mirninsky Ulus": "Мирнинский район",
    "Kaliningrad": "Калининград", "Stavropol": "Ставрополь",
    "Simferopol": "Симферополь", "Sevastopol": "Севастополь",
    # Германия
    "Frankfurt": "Франкфурт", "Frankfurt am Main": "Франкфурт",
    "Berlin": "Берлин", "Munich": "Мюнхен", "Nuremberg": "Нюрнберг",
    "Hamburg": "Гамбург", "Falkenstein": "Фалькенштайн",
    "Cologne": "Кёльн", "Stuttgart": "Штутгарт", "Düsseldorf": "Дюссельдорф",
    "Dusseldorf": "Дюссельдорф", "Duesseldorf": "Дюссельдорф",
    "Leipzig": "Лейпциг", "Dortmund": "Дортмунд", "Essen": "Эссен",
    "Bremen": "Бремен", "Dresden": "Дрезден", "Hanover": "Ганновер",
    "Karlsruhe": "Карлсруэ", "Wiesbaden": "Висбаден", "Augsburg": "Аугсбург",
    # Нидерланды
    "Amsterdam": "Амстердам", "Naaldwijk": "Наалдвейк",
    "Rotterdam": "Роттердам", "The Hague": "Гаага", "Haarlem": "Харлем",
    "Utrecht": "Утрехт", "Eindhoven": "Эйндховен", "Meppel": "Меппель",
    "Groningen": "Гронинген", "Alblasserdam": "Альблассердам",
    "Kerkrade": "Керкраде", "Gemeente Aa en Hunze": "А-эн-Хюнзе",
    # Япония / Корея / Азия
    "Tokyo": "Токио", "Osaka": "Осака", "Yokohama": "Иокогама",
    "Nagoya": "Нагоя", "Sapporo": "Саппоро", "Fukuoka": "Фукуока",
    "Seoul": "Сеул", "Hong Kong": "Гонконг", "Singapore": "Сингапур",
    "Taipei": "Тайбэй", "Bangkok": "Бангкок", "Hanoi": "Ханой",
    "Ho Chi Minh City": "Хошимин", "Jakarta": "Джакарта",
    "Kuala Lumpur": "Куала-Лумпур", "Manila": "Манила",
    "Phnom Penh": "Пномпень", "Mumbai": "Мумбаи", "Delhi": "Дели",
    "New Delhi": "Нью-Дели", "Bangalore": "Бангалор", "Chennai": "Ченнаи",
    "Hyderabad": "Хайдарабад", "Pune": "Пуна", "Kolkata": "Калькутта",
    "Karachi": "Карачи", "Lahore": "Лахор", "Dhaka": "Дака",
    "Kathmandu": "Катманду", "Colombo": "Коломбо", "Beijing": "Пекин",
    "Shanghai": "Шанхай", "Guangzhou": "Гуанчжоу", "Shenzhen": "Шэньчжэнь",
    "Dubai": "Дубай", "Abu Dhabi": "Абу-Даби", "Sharjah": "Шарджа",
    "Doha": "Доха", "Riyadh": "Эр-Рияд", "Tehran": "Тегеран",
    "Baghdad": "Багдад", "Baku": "Баку", "Tbilisi": "Тбилиси",
    "Batumi": "Батуми", "Yerevan": "Ереван", "Almaty": "Алматы",
    "Astana": "Астана", "Tashkent": "Ташкент", "Bishkek": "Бишкек",
    "Minsk": "Минск", "Ulaanbaatar": "Улан-Батор",
    # Северная Европа
    "Oslo": "Осло", "Bergen": "Берген", "Trondheim": "Тронхейм",
    "Stavanger": "Ставангер", "Sandefjord": "Сандефьорд",
    "Helsinki": "Хельсинки", "Espoo": "Эспоо", "Tampere": "Тампере",
    "Oulu": "Оулу", "Tuusula": "Туусула", "Stockholm": "Стокгольм",
    "Gothenburg": "Гётеборг", "Malmo": "Мальмё", "Copenhagen": "Копенгаген",
    "Reykjavik": "Рейкьявик", "Riga": "Рига", "Vilnius": "Вильнюс",
    "Kaunas": "Каунас", "Tallinn": "Таллин", "Tartu": "Тарту",
    # Британия / Ирландия
    "London": "Лондон", "Manchester": "Манчестер", "Glasgow": "Глазго",
    "Edinburgh": "Эдинбург", "Leeds": "Лидс", "Slough": "Слау",
    "Maidenhead": "Мейденхед", "Portsmouth": "Портсмут", "Dublin": "Дублин",
    # США / Канада
    "New York": "Нью-Йорк", "Los Angeles": "Лос-Анджелес",
    "Chicago": "Чикаго", "Houston": "Хьюстон", "Phoenix": "Финикс",
    "Dallas": "Даллас", "San Francisco": "Сан-Франциско", "Seattle": "Сиэтл",
    "Denver": "Денвер", "Miami": "Майами", "Ashburn": "Ашберн",
    "Hillsboro": "Хиллсборо", "Santa Clara": "Санта-Клара",
    "Council Bluffs": "Каунсил-Блафс", "Mountain View": "Маунтин-Вью",
    "Salt Lake City": "Солт-Лейк-Сити", "Kansas City": "Канзас-Сити",
    "Atlanta": "Атланта", "Boston": "Бостон", "Philadelphia": "Филадельфия",
    "Washington": "Вашингтон", "Las Vegas": "Лас-Вегас",
    "Portland": "Портленд", "Austin": "Остин", "Toronto": "Торонто",
    "Columbus": "Колумбус", "Lewes": "Льюис", "Provo-Orem": "Прово",
    "Montreal": "Монреаль", "Vancouver": "Ванкувер", "Ottawa": "Оттава",
    "Beauharnois": "Боарнуа",
    # Европа остальная
    "Paris": "Париж", "Marseille": "Марсель", "Lyon": "Лион",
    "Toulouse": "Тулуза", "Bordeaux": "Бордо", "Lille": "Лилль",
    "Strasbourg": "Страсбург", "Roubaix": "Рубе", "Gravelines": "Гравелин",
    "Vienna": "Вена", "Graz": "Грац", "Linz": "Линц", "Zurich": "Цюрих",
    "Geneva": "Женева", "Bern": "Берн", "Lausanne": "Лозанна",
    "Milan": "Милан", "Rome": "Рим", "Naples": "Неаполь", "Turin": "Турин",
    "Florence": "Флоренция", "Madrid": "Мадрид", "Barcelona": "Барселона",
    "Valencia": "Валенсия", "Seville": "Севилья", "Lisbon": "Лиссабон",
    "Porto": "Порту", "Brussels": "Брюссель", "Antwerp": "Антверпен",
    "Luxembourg": "Люксембург", "Amsterdam-Zuidoost": "Амстердам",
    "Warsaw": "Варшава", "Krakow": "Краков", "Gdansk": "Гданьск",
    "Wroclaw": "Вроцлав", "Poznan": "Познань", "Prague": "Прага",
    "Brno": "Брно", "Ostrava": "Острава", "Plzen": "Пльзень",
    "Budapest": "Будапешт", "Miskolc": "Мишкольц", "Bucharest": "Бухарест",
    "Cluj-Napoca": "Клуж-Напока", "Timisoara": "Тимишоара",
    "Sofia": "София", "Varna": "Варна", "Belgrade": "Белград",
    "Zagreb": "Загреб", "Sarajevo": "Сараево", "Podgorica": "Подгорица",
    "Skopje": "Скопье", "Pristina": "Приштина", "Ljubljana": "Любляна",
    "Bratislava": "Братислава", "Tirana": "Тирана", "Athens": "Афины",
    "Kyiv": "Киев", "Kharkiv": "Харьков", "Odesa": "Одесса",
    "Dnipro": "Днепр", "Lviv": "Львов", "Chisinau": "Кишинёв",
    "Centru": "Центр",
    "Limassol": "Лимасол", "Nicosia": "Никосия", "Valletta": "Валлетта",
    "Tel Aviv": "Тель-Авив", "Haifa": "Хайфа", "Jerusalem": "Иерусалим",
    "Petah Tikva": "Петах-Тиква", "Rehovot": "Реховот",
    # прочее
    "Istanbul": "Стамбул", "Ankara": "Анкара", "Izmir": "Измир",
    "Sydney": "Сидней", "Melbourne": "Мельбурн", "Brisbane": "Брисбен",
    "Auckland": "Окленд", "São Paulo": "Сан-Паулу", "Sao Paulo": "Сан-Паулу",
    "Buenos Aires": "Буэнос-Айрес", "Mexico City": "Мехико",
    "Beauharnois-Salaberry": "Боарнуа",
    "Santiago": "Сантьяго", "Bogotá": "Богота", "Johannesburg": "Йоханнесбург",
    "Cape Town": "Кейптаун", "Casablanca": "Касабланка", "Tunis": "Тунис",
    "Cairo": "Каир", "Nairobi": "Найроби", "Lagos": "Лагос",
}


def geo_lookup(hosts, cache_path):
    """Список хостов -> {host: {"c": страна, "f": флаг, "ct": город}} с кешем."""
    cache = {}
    if os.path.exists(cache_path):
        try:
            with open(cache_path, encoding="utf-8") as f:
                cache = json.load(f)
        except Exception:
            cache = {}
    # города из старого кеша могли остаться английскими: прогоняем через
    # словарь ещё раз — пополнение CITY_RU чинит кеш без новых запросов к API
    touched = False
    for e in cache.values():
        ct = e.get("ct")
        if ct and ct in CITY_RU:
            e["ct"] = CITY_RU[ct]
            touched = True
    if touched:
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False)
        except Exception:
            pass
    now = time.time()
    # «ct» (город) появился не сразу: записи кеша без него считаем устаревшими
    todo = [h for h in hosts
            if not (h in cache and "ct" in cache[h] and now - cache[h]["t"]
                    < GEO_MAX_AGE_DAYS * 86400)]
    if todo:
        log(f"[i] Гео ipwho.is: проверяю {len(todo)} адресов "
            f"(из кеша: {len(hosts) - len(todo)})")

        def one(h):
            ip = h
            if not HOST_IP_RE.match(h):
                try:
                    infos = socket.getaddrinfo(h, None, socket.AF_INET)
                    ip = infos[0][4][0]
                except Exception:
                    try:
                        infos = socket.getaddrinfo(h, None, socket.AF_INET6)
                        ip = infos[0][4][0]
                    except Exception:
                        return h, None
            try:
                req = urllib.request.Request(GEO_API.format(ip=ip),
                                             headers={"User-Agent": UA})
                with urllib.request.urlopen(req, timeout=12) as resp:
                    d = json.loads(resp.read().decode("utf-8", "replace"))
                if d.get("success"):
                    cc = d.get("country_code") or ""
                    city_en = (d.get("city") or "").strip()
                    return h, {
                        "c": COUNTRY_RU.get(cc, d.get("country") or ""),
                        "f": (d.get("flag") or {}).get("emoji") or "",
                        "ct": CITY_RU.get(city_en, city_en),
                        "cc": cc, "t": time.time()}
            except Exception:
                pass
            return h, None

        with ThreadPoolExecutor(8) as ex:
            for h, e in ex.map(one, todo):
                if e:
                    cache[h] = e
        try:
            with open(cache_path, "w", encoding="utf-8") as f:
                json.dump(cache, f, ensure_ascii=False)
        except Exception as e:
            log(f"  [!] кеш гео не записан: {e}")
    return cache


def relabel(srv, cat, idx, geo):
    """Проставляет имя «🇬🇧 Британия — Лондон».

    У vless/trojan/ss/hysteria2/… имя живёт в #фрагменте ссылки, и мы
    просто заменяем его. У vmess и ssr клиент имя из фрагмента НЕ читает —
    оно зашито внутри base64-полезной нагрузки (поле ps / remarks), поэтому
    для них пересобираем payload с новым именем.
    """
    g = geo.get(srv["host"]) or {}
    place = g.get("c", "")
    if g.get("ct"):
        place += " — " + g["ct"]
    elif not place:
        place = srv["host"]
    name = (g.get("f", "") + " " + place).strip()
    srv["uri"] = set_uri_name(srv["uri"], name)
    srv["name"] = name


def set_uri_name(uri, name):
    """Возвращает uri с именем name (fragment или ps/remarks внутри base64)."""
    if uri.startswith("vmess://"):
        # vmess: base64-JSON, имя в поле ps; '?params' и '#name' отбрасываем —
        # клиент их не читает
        payload = uri[len("vmess://"):].split("#")[0].split("?")[0]
        j = b64d(payload)
        if j:
            try:
                cfg = json.loads(j)
                cfg["ps"] = name
                b = base64.b64encode(
                    json.dumps(cfg, ensure_ascii=False,
                               separators=(",", ":")).encode()).decode()
                return "vmess://" + b
            except Exception:
                pass
        return uri  # не получилось декодировать — оставляем как есть
    if uri.startswith("ssr://"):
        # ssr: base64 'host:port:proto:method:obfs:b64pass/?params', имя —
        # параметр remarks (base64) в хвосте
        dec = b64d(uri[len("ssr://"):])
        if dec and "/?" in dec:
            main, tail = dec.split("/?", 1)
            kv = {}
            for part in tail.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    kv[k] = v
            kv["remarks"] = base64.b64encode(name.encode()).decode()
            tail = "&".join(f"{k}={v}" for k, v in kv.items())
            return "ssr://" + b64e(main + "/?" + tail)
    # остальные протоколы: имя в #фрагменте
    if "#" in uri:
        uri = uri.split("#", 1)[0]
    return uri + "#" + name


def b64e(s):
    """str -> обычный base64 без переносов строк."""
    return base64.b64encode(s.encode("utf-8")).decode("ascii")


def log(msg):
    print(msg, flush=True)


# ----------------------------------------------------------------------------- base64

def b64d(s):
    """Base64 (обычный/URL-safe, без паддинга) -> str или None."""
    s = re.sub(r"\s+", "", s).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s).decode("utf-8", "replace")
    except Exception:
        return None


# ----------------------------------------------------------------------------- сеть: скачивание

def fetch_lines(url, timeout=45, src_no=0):
    """Скачивает источник, возвращает список ссылок.

    src_no — номер источника для лога: сами URL нигде не печатаем,
    логи Actions в публичном репозитории видны всем.
    """
    last_err = None
    for _ in range(2):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                if (resp.headers.get("Content-Encoding") or "").lower() == "gzip":
                    data = gzip.decompress(data)
            body = data.decode("utf-8", "replace").strip().lstrip("\ufeff")
            # Целый файл в base64? (нет "://" в начале, но есть после декодирования)
            if body and "://" not in body[:4096]:
                dec = b64d(body)
                if dec and "://" in dec:
                    body = dec
            out = []
            for ln in body.splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#") or ln.startswith("//"):
                    continue
                if LINK_RE.match(ln):
                    out.append(ln)
            return out
        except Exception as e:
            last_err = e
            time.sleep(2)
    log(f"  [!] источник #{src_no}: недоступен ({type(last_err).__name__})")
    return []


# ----------------------------------------------------------------------------- утилиты парсинга

def qparams(query):
    """Разбор query-строки БЕЗ превращения '+' в пробел (важно для reality pbk)."""
    q = {}
    for part in (query or "").split("&"):
        if not part:
            continue
        k, _, v = part.partition("=")
        q[unquote(k)] = unquote(v)
    return q


def split_hostport(s):
    """'host:port' или '[ipv6]:port' -> (host, port). Иначе (None, None)."""
    s = (s or "").strip()
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
        return (m.group(1), int(m.group(2))) if m else (None, None)
    if ":" in s:
        h, p = s.rsplit(":", 1)
        if p.isdigit():
            return (h.strip("[]"), int(p))
    return (None, None)


def make(proto, uri, host, port, cred, engine, out):
    return {"proto": proto, "uri": uri, "host": host, "port": port,
            "cred": cred or "", "engine": engine, "out": out,
            "alive": False, "src": None, "cat": None}


def build_stream_xray(q, host, default_sec=""):
    """Собирает streamSettings для Xray по параметрам ссылки. None -> не тестировать."""
    net = (q.get("type") or q.get("network") or "tcp").lower()
    if net == "h2":
        net = "http"
    if net in ("kcp", "quic", "domainsocket", "unix"):
        return None
    if (q.get("headerType") or "").lower() not in ("", "none"):
        return None  # tcp с http-заголовками и прочее — не тестируем
    sec = (q.get("security") or default_sec or "").lower()
    if not sec and q.get("sni"):
        sec = "tls"  # sni без security почти всегда tls
    stream = {"network": net}
    if sec == "reality":
        if not q.get("pbk"):
            return None
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": q.get("sni") or host,
            "fingerprint": q.get("fp") or "chrome",
            "publicKey": q["pbk"],
            "shortId": q.get("sid") or "",
            "spiderX": unquote(q.get("spx") or "/"),
        }
    elif sec == "tls":
        stream["security"] = "tls"
        ts = {"allowInsecure": True, "serverName": q.get("sni") or q.get("host") or host}
        if q.get("alpn"):
            ts["alpn"] = [a for a in q["alpn"].split(",") if a]
        if q.get("fp"):
            ts["fingerprint"] = q["fp"]
        stream["tlsSettings"] = ts
    elif sec in ("", "none"):
        pass
    else:
        return None
    path = unquote(q.get("path") or "/")
    qhost = q.get("host") or host
    if net == "ws":
        stream["wsSettings"] = {"path": path or "/", "headers": {"Host": qhost}}
    elif net == "grpc":
        sn = q.get("serviceName") or q.get("path") or ""
        if not sn:
            return None
        stream["grpcSettings"] = {"serviceName": sn}
    elif net == "http":
        stream["httpSettings"] = {"host": [qhost], "path": path}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path or "/", "host": qhost}
    elif net in ("xhttp", "splithttp"):
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": path or "/", "host": qhost,
                                   "mode": q.get("mode") or "auto"}
    elif net == "tcp":
        pass
    else:
        return None
    return stream


# ----------------------------------------------------------------------------- парсеры протоколов

def parse_vless(link):
    u = urlparse(link)
    host = (u.hostname or "").strip("[]")
    uuid = unquote(u.username or "")
    try:
        port = u.port
    except ValueError:
        return None
    if not host or not port or not uuid:
        return None
    q = qparams(u.query)
    stream = build_stream_xray(q, host)
    user = {"id": uuid, "encryption": q.get("encryption") or "none"}
    if q.get("flow"):
        user["flow"] = q["flow"]
    out = {"tag": "proxy", "protocol": "vless",
           "settings": {"vnext": [{"address": host, "port": port, "users": [user]}]}}
    if stream:
        out["streamSettings"] = stream
    return make("vless", link, host, port, uuid, "xray" if stream else None, out)


def parse_vmess(link):
    # хвост '?params' и '#name' — не часть base64 (некоторые клиенты добавляют '?fp=...')
    payload = link[len("vmess://"):].split("#")[0].split("?")[0]
    j = b64d(payload)
    if not j:
        return None
    try:
        cfg = json.loads(j)
    except Exception:
        return None
    host = str(cfg.get("add") or "").strip().strip("[]")
    try:
        port = int(cfg.get("port"))
    except Exception:
        return None
    cid = str(cfg.get("id") or "").strip()
    if not host or not port or not cid:
        return None
    try:
        aid = int(cfg.get("aid") or 0)
    except Exception:
        aid = 0
    net = str(cfg.get("net") or "tcp").lower()
    q = {
        "type": net,
        "security": "tls" if str(cfg.get("tls") or "").lower() == "tls" else "",
        "sni": str(cfg.get("sni") or ""),
        "host": str(cfg.get("host") or ""),
        "path": str(cfg.get("path") or ""),
        "alpn": str(cfg.get("alpn") or ""),
        "fp": str(cfg.get("fp") or ""),
    }
    if net in ("tcp", "kcp"):
        t = str(cfg.get("type") or "")
        if t and t.lower() != "none":
            q["headerType"] = t
    stream = build_stream_xray(q, host)
    out = {"tag": "proxy", "protocol": "vmess",
           "settings": {"vnext": [{"address": host, "port": port, "users": [
               {"id": cid, "alterId": aid, "security": str(cfg.get("scy") or "auto")}]}]}}
    if stream:
        out["streamSettings"] = stream
    return make("vmess", link, host, port, cid, "xray" if stream else None, out)


def parse_trojan(link):
    u = urlparse(link)
    host = (u.hostname or "").strip("[]")
    pwd = unquote(u.username or "")
    try:
        port = u.port
    except ValueError:
        return None
    if not host or not port or not pwd:
        return None
    q = qparams(u.query)
    stream = build_stream_xray(q, host, default_sec="tls")
    out = {"tag": "proxy", "protocol": "trojan",
           "settings": {"servers": [{"address": host, "port": port, "password": pwd}]}}
    if stream:
        out["streamSettings"] = stream
    return make("trojan", link, host, port, pwd, "xray" if stream else None, out)


def parse_ss(link):
    body = link[len("ss://"):]
    main = body.split("#")[0]
    if "?" in main:
        main, qs = main.split("?", 1)
        q = qparams(qs)
    else:
        q = {}
    main = main.split("/")[0]
    if "@" in main:
        userinfo, hostport = main.rsplit("@", 1)
        host, port = split_hostport(hostport)
        mdpw = b64d(userinfo)
        if mdpw and ":" in mdpw:
            method, password = mdpw.split(":", 1)
        elif ":" in userinfo:
            method, password = (unquote(x) for x in userinfo.split(":", 1))
        else:
            return None
    else:
        dec = b64d(main)
        if not dec or "@" not in dec:
            return None
        userinfo, hostport = dec.rsplit("@", 1)
        host, port = split_hostport(hostport)
        if ":" not in userinfo:
            return None
        method, password = userinfo.split(":", 1)
    if not host or not port or not method or password is None:
        return None
    cred = f"{method}:{password}"
    if q.get("plugin"):
        return make("ss", link, host, port, cred, None, None)  # плагины не тестируем
    out = {"tag": "proxy", "protocol": "shadowsocks",
           "settings": {"servers": [{"address": host, "port": port,
                                     "method": method, "password": password}]}}
    return make("ss", link, host, port, cred, "xray", out)


def parse_ssr(link):
    dec = b64d(link[len("ssr://"):])
    if not dec:
        return None
    main = dec.split("/")[0].split("?")[0]
    parts = main.split(":")
    if len(parts) < 6:
        return None
    host = parts[0].strip("[]")
    if not parts[1].isdigit():
        return None
    return make("ssr", link, host, int(parts[1]), "", None, None)


def parse_hysteria2(link):
    rest = link.split("://", 1)[1]
    main = rest.split("#")[0]
    if "?" in main:
        main, qs = main.split("?", 1)
        q = qparams(qs)
    else:
        q = {}
    if "@" not in main:
        return None
    userinfo, hostport = main.rsplit("@", 1)
    host, port = split_hostport(hostport)
    pwd = unquote(userinfo)
    if not host or not port or not pwd:
        return None
    out = {"type": "hysteria2", "tag": "proxy", "server": host,
           "server_port": port, "password": pwd}
    tls = {"enabled": True, "server_name": q.get("sni") or host,
           "insecure": q.get("insecure", "1") != "0"}
    if q.get("alpn"):
        tls["alpn"] = [a for a in q["alpn"].split(",") if a]
    out["tls"] = tls
    if q.get("obfs") and q["obfs"] != "none" and q.get("obfs-password"):
        out["obfs"] = {"type": q["obfs"], "password": q["obfs-password"]}
    return make("hysteria2", link, host, port, pwd, "singbox", out)


def parse_tuic(link):
    rest = link.split("://", 1)[1]
    main = rest.split("#")[0]
    if "?" in main:
        main, qs = main.split("?", 1)
        q = qparams(qs)
    else:
        q = {}
    if "@" not in main:
        return None
    userinfo, hostport = main.rsplit("@", 1)
    host, port = split_hostport(hostport)
    if not host or not port or ":" not in userinfo:
        return None  # tuic v4 без пароля не тестируем
    uuid, pwd = (unquote(x) for x in userinfo.split(":", 1))
    if not uuid or not pwd:
        return None
    out = {"type": "tuic", "tag": "proxy", "server": host, "server_port": port,
           "uuid": uuid, "password": pwd,
           "congestion_control": q.get("congestion_control") or "bbr",
           "udp_relay_mode": q.get("udp_relay_mode") or "native"}
    out["tls"] = {"enabled": True, "server_name": q.get("sni") or host,
                  "insecure": (q.get("allow_insecure") or q.get("insecure") or "1") != "0"}
    return make("tuic", link, host, port, uuid, "singbox", out)


def parse_anytls(link):
    rest = link.split("://", 1)[1]
    main = rest.split("#")[0]
    if "?" in main:
        main, qs = main.split("?", 1)
        q = qparams(qs)
    else:
        q = {}
    if "@" not in main:
        return None
    userinfo, hostport = main.rsplit("@", 1)
    host, port = split_hostport(hostport)
    pwd = unquote(userinfo)
    if not host or not port or not pwd:
        return None
    out = {"type": "anytls", "tag": "proxy", "server": host, "server_port": port,
           "password": pwd,
           "tls": {"enabled": True, "server_name": q.get("sni") or host,
                   "insecure": (q.get("allow_insecure") or q.get("insecure") or "1") != "0"}}
    return make("anytls", link, host, port, pwd, "singbox", out)


def parse_generic(link):
    """socks/http/прочее — только адрес для проверки порта."""
    try:
        u = urlparse(link)
        host = (u.hostname or "").strip("[]")
        port = u.port
    except ValueError:
        return None
    if not host or not port:
        return None
    proto = link.split("://", 1)[0].lower()
    return make(proto, link, host, port, "", None, None)


def parse_link(link):
    scheme = link.split("://", 1)[0].lower()
    if scheme == "hy2":
        scheme = "hysteria2"
    parser = {
        "vless": parse_vless, "vmess": parse_vmess, "trojan": parse_trojan,
        "ss": parse_ss, "ssr": parse_ssr, "hysteria2": parse_hysteria2,
        "tuic": parse_tuic, "anytls": parse_anytls,
    }.get(scheme)
    try:
        srv = parser(link) if parser else parse_generic(link)
    except Exception:
        srv = None
    if srv is None:
        # даже нераспознанную ссылку попробуем проверить по порту
        try:
            srv = parse_generic(link)
        except Exception:
            srv = None
    return srv


def srv_key(srv):
    h = ""
    if srv["out"]:
        h = re.sub(r"\W+", "", json.dumps(srv["out"], sort_keys=True))[:12]
    return f"{srv['proto']}|{srv['host']}|{srv['port']}|{srv['cred']}|{h}"


# ----------------------------------------------------------------------------- этап 1: порт

def tcp_check(host, port, timeout, cache, lock):
    key = (host, port)
    with lock:
        if key in cache:
            return cache[key]
    ok = False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            ok = True
    except OSError:
        ok = False
    with lock:
        cache[key] = ok
    return ok


# ----------------------------------------------------------------------------- SOCKS5-клиент (stdlib)

def recv_exact(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            raise IOError("socks: eof")
        buf += c
    return buf


def socks5_connect(proxy_port, dst_host, dst_port, timeout):
    s = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(b"\x05\x01\x00")
    resp = recv_exact(s, 2)
    if resp[0] != 5 or resp[1] != 0:
        raise IOError("socks: handshake failed")
    addr = dst_host.encode()
    s.sendall(b"\x05\x01\x00\x03" + bytes([len(addr)]) + addr +
              dst_port.to_bytes(2, "big"))
    resp = recv_exact(s, 4)
    if resp[1] != 0:
        raise IOError(f"socks: connect rejected ({resp[1]})")
    atyp = resp[3]
    if atyp == 1:
        recv_exact(s, 6)
    elif atyp == 3:
        ln = recv_exact(s, 1)[0]
        recv_exact(s, ln + 2)
    elif atyp == 4:
        recv_exact(s, 18)
    return s


def http_via_socks(local_port, deadline):
    """Качает тестовую страницу через локальный SOCKS. True = туннель жив."""
    for host, port, path in TEST_URLS:
        remaining = deadline - time.time()
        if remaining <= 1.5:
            return False
        tmo = min(10.0, remaining)
        s = None
        try:
            s = socks5_connect(local_port, host, port, timeout=tmo)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: {UA}\r\nConnection: close\r\n\r\n")
            s.sendall(req.encode())
            s.settimeout(tmo)
            data = s.recv(2048)
            line = data.split(b"\r\n", 1)[0].decode("latin1", "replace")
            if re.match(r"^HTTP/\S+\s+\d{3}\b", line):
                return True  # любой валидный HTTP-ответ = туннель работает
        except Exception:
            continue
        finally:
            if s:
                try:
                    s.close()
                except Exception:
                    pass
    return False


# ----------------------------------------------------------------------------- этап 2: реальный тест

class PortPool:
    def __init__(self, base, size):
        self.free = [base + i for i in range(size)]
        self.lock = threading.Lock()

    def acquire(self):
        with self.lock:
            return self.free.pop() if self.free else None

    def release(self, p):
        with self.lock:
            self.free.append(p)


def build_full_config(engine, srv, local_port):
    if engine == "xray":
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [{"tag": "in", "listen": "127.0.0.1", "port": local_port,
                          "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [srv["out"], {"tag": "direct", "protocol": "freedom"}],
            "routing": {"rules": [{"type": "field", "outboundTag": "proxy",
                                   "network": "tcp,udp"}]},
        }
    return {
        "log": {"level": "warn"},
        "inbounds": [{"type": "socks", "tag": "in", "listen": "127.0.0.1",
                      "listen_port": local_port}],
        "outbounds": [srv["out"], {"type": "direct", "tag": "direct"}],
    }


def deep_test(srv, binary, engine, pool, budget, debug, dbg_counter):
    local_port = pool.acquire()
    if local_port is None:
        return False
    proc = None
    cfgpath = None
    ok = False
    try:
        cfg = build_full_config(engine, srv, local_port)
        fd, cfgpath = tempfile.mkstemp(suffix=".json", prefix="vpncheck_")
        with os.fdopen(fd, "w") as f:
            json.dump(cfg, f)
        argv = [binary, "run", "-c", cfgpath]
        err = subprocess.DEVNULL
        if debug and dbg_counter[0] < 15:
            dbg_counter[0] += 1
            err = open(f"/tmp/deep_dbg_{dbg_counter[0]}.log", "wb")
        proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=err)
        t0 = time.time()
        deadline = t0 + budget
        ready = False
        while time.time() < t0 + 5.0:
            if proc.poll() is not None:
                break  # процесс упал (битый конфиг)
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.4):
                    ready = True
                    break
            except OSError:
                time.sleep(0.25)
        if ready:
            ok = http_via_socks(local_port, deadline)
    except Exception:
        ok = False
    finally:
        if proc is not None:
            try:
                proc.terminate()
                proc.wait(timeout=2)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if cfgpath:
            try:
                os.unlink(cfgpath)
            except Exception:
                pass
        pool.release(local_port)
    return ok


# ----------------------------------------------------------------------------- статистика / README

def render_stats(stats):
    lines = [STATS_START, "## 📊 Статистика последней проверки", "",
             f"**Время проверки:** {stats['time']} UTC", "",
             "| Метрика | Значение |", "| --- | --- |",
             f"| Источников скачано | {stats['src_ok']}/{stats['src_total']} |",
             f"| Ссылок получено | {stats['links']} |",
             f"| Уникальных серверов | {stats['unique']} |",
             f"| Порт открыт (этап 1) | {stats['port_ok']} |",
             f"| Прошли реальный тест (этап 2) | {stats['deep_ok']} |",
             f"| Прошли только по порту | {stats['port_only_ok']} |",
             f"| **Итого в подписке** | **{stats['final']}** |",
             f"| 🤍 «Белый» (для блокировок) | {stats['white']} |",
             f"| 🖤 «ЧС» (обычный интернет) | {stats['black']} |", ""]
    if not stats.get("first_run"):
        delta = stats["final"] - stats.get("prev_alive", stats["final"])
        dsign = "+" if delta >= 0 else "−"
        lines += [f"**Динамика за последние 3 часа:** умерло "
                  f"{stats.get('died', 0)}, появилось новых "
                  f"{stats.get('fresh', 0)} — {stats.get('prev_alive', '?')} → "
                  f"{stats['final']} ({dsign}{abs(delta)})", ""]
    if stats["proto"]:
        lines += ["### По протоколам", "",
                  "| Протокол | Серверов | В подписке | Белый | ЧС |",
                  "| --- | --- | --- | --- | --- |"]
        for p, tot in sorted(stats["proto"].items(), key=lambda x: -x[1]):
            lines.append(f"| {p} | {tot} | {stats['proto_alive'].get(p, 0)} | "
                         f"{stats['proto_white'].get(p, 0)} | "
                         f"{stats['proto_black'].get(p, 0)} |")
        lines.append("")
    if stats["countries"]:
        lines += ["### По странам", "",
                  "| Страна | В подписке |", "| --- | --- |"]
        for c, n in sorted(stats["countries"].items(), key=lambda x: -x[1]):
            lines.append(f"| {c} | {n} |")
        lines.append("")
    # источники намеренно НЕ показываем: репозиторий публичный, а список
    # источников — секрет
    lines.append(STATS_END)
    return "\n".join(lines)


def update_readme(path, stats):
    block = render_stats(stats)
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            content = f.read()
        if STATS_START in content and STATS_END in content:
            new = re.sub(re.escape(STATS_START) + r".*?" + re.escape(STATS_END),
                         block.replace("\\", "\\\\"), content, flags=re.S)
        else:
            new = content.rstrip() + "\n\n" + block + "\n"
    else:
        new = "# VPN Server Checker\n\n" + block + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.write(new)


# ----------------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="VPN server checker")
    ap.add_argument("--sources", default="sources.txt")
    ap.add_argument("--out-dir", default=".")
    ap.add_argument("--readme", default="README.md")
    ap.add_argument("--bin-dir", default="bin")
    ap.add_argument("--deep", action="store_true", help="этап 2: реальный тест")
    ap.add_argument("--no-deep", dest="deep", action="store_false")
    ap.add_argument("--port-timeout", type=float, default=8.0)
    ap.add_argument("--deep-timeout", type=float, default=18.0)
    ap.add_argument("--port-workers", type=int, default=200)
    ap.add_argument("--deep-workers", type=int, default=20)
    ap.add_argument("--base-port", type=int, default=20000)
    ap.add_argument("--limit", type=int, default=0, help="для отладки: не более N серверов")
    ap.add_argument("--debug", action="store_true")
    args = ap.parse_args()

    t_start = time.time()

    # --- источники ---
    with open(args.sources, encoding="utf-8") as f:
        sources = [ln.strip() for ln in f
                   if ln.strip() and not ln.strip().startswith("#")]
    log(f"[i] Источников в списке: {len(sources)}")
    raw_links = []
    src_ok = 0
    for i, url in enumerate(sources):
        lines = fetch_lines(url, src_no=i + 1)
        if lines:
            src_ok += 1
        log(f"  [{i + 1}/{len(sources)}] источник #{i + 1} -> {len(lines)} ссылок")
        for ln in lines:
            raw_links.append((i, ln))
    log(f"[i] Всего ссылок скачано: {len(raw_links)}")

    # --- парсинг + дедуп ---
    servers, seen, bad = [], set(), 0
    for src, ln in raw_links:
        srv = parse_link(ln)
        if not srv:
            bad += 1
            continue
        if args.limit and len(seen) >= args.limit:
            break
        k = srv_key(srv)
        if k in seen:
            continue
        seen.add(k)
        srv["src"] = src
        servers.append(srv)
    log(f"[i] Уникальных серверов: {len(servers)}"
        + (f" (нераспознано: {bad})" if bad else ""))

    if not servers:
        log("[!] Ни одного сервера — проверяй sources.txt")
        return

    # --- этап 1: порты ---
    log(f"[Этап 1] Проверка портов: {len(servers)} серверов, "
        f"{args.port_workers} потоков, таймаут {args.port_timeout}s")
    cache, lock = {}, threading.Lock()
    done = 0
    with ThreadPoolExecutor(args.port_workers) as ex:
        futs = {ex.submit(tcp_check, s["host"], s["port"], args.port_timeout,
                          cache, lock): s for s in servers}
        for fut in as_completed(futs):
            s = futs[fut]
            if fut.result():
                s["port_ok"] = True
            done += 1
            if done % 250 == 0:
                log(f"  … {done}/{len(servers)}")
    port_alive = [s for s in servers if s.get("port_ok")]
    log(f"[Этап 1] Порт открыт: {len(port_alive)}/{len(servers)}")

    # --- этап 2: реальный тест ---
    deep_list = [s for s in port_alive if s["engine"]]
    port_only = [s for s in port_alive if not s["engine"]]
    for s in port_only:
        s["alive"] = True
    deep_ok = 0
    if args.deep and deep_list:
        bins = {"xray": os.path.join(args.bin_dir, "xray"),
                "singbox": os.path.join(args.bin_dir, "sing-box")}
        missing = [e for e, b in bins.items() if not os.path.exists(b)]
        if missing:
            log(f"[!] Нет бинарников {missing} — эти протоколы пойдут только по порту")
            for s in deep_list:
                if s["engine"] in missing:
                    s["engine"], s["alive"] = None, True
            deep_list = [s for s in port_alive if s["engine"]]
        if deep_list:
            log(f"[Этап 2] Реальный тест: {len(deep_list)} серверов "
                f"({args.deep_workers} потоков, бюджет {args.deep_timeout}s)")
            pool = PortPool(args.base_port, args.deep_workers + 4)
            done = 0
            dbg = [0]
            with ThreadPoolExecutor(args.deep_workers) as ex:
                futs = {ex.submit(deep_test, s, bins[s["engine"]], s["engine"],
                                  pool, args.deep_timeout, args.debug, dbg): s
                        for s in deep_list}
                for fut in as_completed(futs):
                    s = futs[fut]
                    if fut.result():
                        s["alive"] = True
                        deep_ok += 1
                    done += 1
                    if done % 25 == 0 or done == len(deep_list):
                        log(f"  … {done}/{len(deep_list)} (живых: {deep_ok})")
    elif not args.deep:
        log("[i] Этап 2 выключен (--no-deep): берём все с открытым портом")
        for s in deep_list:
            s["alive"] = True

    # --- итоги ---
    alive = [s for s in servers if s["alive"]]
    log(f"[i] Итог в подписке: {len(alive)} серверов "
        f"(реальный тест: {deep_ok}, только порт: {len(port_only)})")

    # --- классификация Белый/ЧС + гео + имена DangerVPN ---
    for s in alive:
        s["cat"] = classify(s)
    white = [s for s in alive if s["cat"] == "white"]
    black = [s for s in alive if s["cat"] == "black"]
    log(f"[i] Категории: «Белый» {len(white)}, «ЧС» {len(black)}")

    geo = geo_lookup(sorted({s["host"] for s in alive}),
                     os.path.join(args.out_dir, GEO_CACHE))

    # сервер-заголовок в начале подписки: виден в клиенте как первая строка
    # списка и сообщает, что подписка живая и как часто обновляется.
    # Это псевдо-сервер (127.0.0.1:1) — подключаться к нему не нужно.
    header_uri = ("vless://info@127.0.0.1:1?security=none&encryption=none"
                  "#♻️ DangerVPN · Автообновление каждые 3 часа")

    def write_subs(name, group):
        # одинаковые имена внутри одного файла различаем номером:
        # «🇩🇪 Германия — Франкфурт», «… — Франкфурт 2», «… — Франкфурт 3»
        # (set_uri_name знает, куда имя писать: fragment или внутрь base64)
        seen = {}
        uris = [header_uri]
        for s in group:
            n = seen.get(s["name"], 0) + 1
            seen[s["name"]] = n
            if n > 1:
                uris.append(set_uri_name(s["uri"], s["name"] + f" {n}"))
            else:
                uris.append(s["uri"])
        plain = "\n".join(uris) + "\n"
        with open(os.path.join(args.out_dir, name + "_plain.txt"), "w",
                  encoding="utf-8") as f:
            f.write(plain)
        with open(os.path.join(args.out_dir, name + "_base64.txt"), "w",
                  encoding="utf-8") as f:
            f.write(base64.b64encode(plain.encode()).decode("ascii"))

    os.makedirs(args.out_dir, exist_ok=True)

    # сортировка: страны по алфавиту (по русскому названию), внутри — по городу
    def sort_key(s):
        g = geo.get(s["host"]) or {}
        return (g.get("c") or "яя", g.get("ct") or "", s["host"], s["port"])

    white.sort(key=sort_key)
    black.sort(key=sort_key)
    for i, s in enumerate(white, 1):
        relabel(s, "white", i, geo)
    for i, s in enumerate(black, 1):
        relabel(s, "black", i, geo)
    # общий sub: сначала весь «Белый», за ним «ЧС» — обе группы уже отсортированы
    alive[:] = white + black
    write_subs("sub", alive)
    write_subs("white", white)
    write_subs("black", black)

    # главный файл подписки — Happ-формат: plain-ссылки + заголовки профиля.
    # Без псевдо-сервера-заголовка: его заменяют поля #profile-*
    announce = "♻️ DangerVPN · Автообновление каждые 3 часа"
    sub_lines = [
        "#profile-title: DangerVPN 🚀",
        "#announce: base64:" + b64e(announce),
        "#profile-update-interval: 3",
    ] + [s["uri"] for s in alive]
    with open(os.path.join(args.out_dir, "sub"), "w", encoding="utf-8") as f:
        f.write("\n".join(sub_lines) + "\n")

    log(f"[i] Записано: sub (Happ), sub_plain.txt, sub_base64.txt, "
        f"white_*.txt, black_*.txt, README.md")

    # --- динамика: кто умер и кто появился с прошлого прогона ---
    # state.json хранит хосты живого набора с прошлого раза; разница
    # попадает в README, а смена набора и есть «замена умерших».
    state_path = os.path.join(args.out_dir, "state.json")
    prev_hosts, first_run = set(), True
    if os.path.exists(state_path):
        try:
            with open(state_path, encoding="utf-8") as f:
                prev_hosts = set(json.load(f).get("hosts") or [])
                first_run = False
        except Exception:
            prev_hosts, first_run = set(), True
    cur_hosts = {s["host"] for s in alive}
    died = prev_hosts - cur_hosts
    fresh = cur_hosts - prev_hosts
    with open(state_path, "w", encoding="utf-8") as f:
        json.dump({"hosts": sorted(cur_hosts),
                   "t": time.strftime("%Y-%m-%d %H:%M", time.gmtime())}, f)
    log(f"[i] Динамика: умерло {len(died)}, новых {len(fresh)} "
        f"({len(prev_hosts)} → {len(cur_hosts)})")

    # --- статистика в README ---
    src_stats = {}
    for s in servers:
        t, a = src_stats.get(s["src"], (0, 0))
        src_stats[s["src"]] = (t + 1, a + (1 if s["alive"] else 0))
    stats = {
        "time": time.strftime("%Y-%m-%d %H:%M", time.gmtime()),
        "src_ok": src_ok, "src_total": len(sources),
        "links": len(raw_links), "unique": len(servers),
        "port_ok": len(port_alive), "deep_ok": deep_ok,
        "port_only_ok": len(port_only), "final": len(alive),
        "white": len(white), "black": len(black),
        "proto": Counter(s["proto"] for s in servers),
        "proto_alive": Counter(s["proto"] for s in alive if s["proto"]),
        "proto_white": Counter(s["proto"] for s in white if s["proto"]),
        "proto_black": Counter(s["proto"] for s in black if s["proto"]),
        "countries": Counter(
            ((geo.get(s["host"]) or {}).get("f", "") + " "
             + (geo.get(s["host"]) or {}).get("c", "")).strip()
            for s in alive if (geo.get(s["host"]) or {}).get("c")),
        "sources": list(enumerate(sources)),
        "src_stats": src_stats,
        "died": len(died), "fresh": len(fresh),
        "prev_alive": len(prev_hosts), "first_run": first_run,
    }
    update_readme(args.readme, stats)
    log(f"[i] {args.readme} обновлён")
    log(f"[i] Готово за {time.time() - t_start:.0f}s")


if __name__ == "__main__":
    main()
