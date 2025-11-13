# main.py
# Copyright (c) 2025 RovneX
# Licensed under the MIT License

import aiohttp
import asyncio
import re
import json
import base64
import logging
import os
import random
from urllib.parse import urlparse, urlunparse, quote
from collections import defaultdict


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
KEYS_DIR = os.path.join(ROOT, "Keys")
ALL_DIR = os.path.join(KEYS_DIR, "All")
PROT_DIR = os.path.join(KEYS_DIR, "Protocols")
CONFIG_PATH = os.path.join(os.path.dirname(__file__), "config.json")

os.makedirs(ALL_DIR, exist_ok=True)
for p in ("VLess", "VMess", "Shadowsocks"):
    os.makedirs(os.path.join(PROT_DIR, p), exist_ok=True)

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")


URI_RE = re.compile(r"(vmess://\S+|vless://\S+|ss://\S+)", re.IGNORECASE)
IP_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})")


def find_links(text):
    return URI_RE.findall(text)

def extract_ip(link):
    m = IP_RE.search(link)
    return m.group(1) if m else None

def safe_b64_decode(s):
    s2 = s.strip().replace("\n", "")
    if len(s2) % 4:
        s2 += "=" * (4 - len(s2) % 4)
    return base64.urlsafe_b64decode(s2.encode())

def safe_b64_encode(b):
    return base64.urlsafe_b64encode(b).decode().replace("=", "")


def watermark_vmess(uri_body, tag, flag, proto):
    frag = f"{flag}[{tag}]-{proto}{flag}"
    try:
        j = json.loads(safe_b64_decode(uri_body).decode())
        ps = j.get("ps", "")
        if tag not in ps:
            j["ps"] = f"{ps} | {frag}" if ps else frag
        return "vmess://" + safe_b64_encode(json.dumps(j, separators=(",", ":")).encode())
    except Exception:
        return "vmess://" + uri_body + "#" + quote(frag)

def watermark_vless(uri, tag, flag, proto):
    frag = f"{flag}[{tag}]-{proto}{flag}"
    try:
        parsed = urlparse(uri)
        new_parsed = parsed._replace(fragment=frag)
        return urlunparse(new_parsed)
    except Exception:
        return uri + "#" + quote(frag)

def watermark_ss(uri, tag, flag, proto):
    frag = f"{flag}[{tag}]-{proto}{flag}"
    return uri + "#" + quote(frag)


def classify_and_maybe_watermark(link, chance, tag, flag):
    l = link.strip()
    proto = None
    if l.lower().startswith("vmess://"):
        proto = "VMess"
        if random.random() < chance:
            return proto, watermark_vmess(l[8:], tag, flag, proto)
    elif l.lower().startswith("vless://"):
        proto = "VLess"
        if random.random() < chance:
            return proto, watermark_vless(l, tag, flag, proto)
    elif l.lower().startswith("ss://"):
        proto = "Shadowsocks"
        if random.random() < chance:
            return proto, watermark_ss(l, tag, flag, proto)
    return proto, l


async def geolocate_ip(ip, session):
    if not ip:
        return None
    urls = [
        f"https://ipapi.co/{ip}/country_name/",
        f"https://ipinfo.io/{ip}/country"
    ]
    for u in urls:
        try:
            async with session.get(u, timeout=8) as r:
                if r.status == 200:
                    t = (await r.text()).strip()
                    if t:
                        return t
        except Exception:
            continue
    return None


async def fetch_text(url, session):
    try:
        async with session.get(url, timeout=25, headers={"User-Agent": "V2Fetcher/1.0"}) as r:
            if r.status == 429:
                logging.warning("Rate limit from %s", url)
                return "RATE_LIMIT"
            if r.status == 200:
                return await r.text()
    except Exception as e:
        logging.warning("Fetch failed %s: %s", url, e)
    return ""


async def process_all(cfg):
    separate = cfg.get("separate", {})
    full = cfg.get("full", [])
    chance = float(cfg.get("modify_chance", 0.4))
    tag = cfg.get("watermark_tag", "gh:RovneX")

    aggregated = defaultdict(lambda: {"All": set(), "VMess": set(), "VLess": set(), "Shadowsocks": set()})

    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=20)) as s:
        
        for country, url in separate.items():
            if not url:
                continue
            logging.info("Fetching %s...", country)
            text = await fetch_text(url, s)
            if not text:
                continue
            links = find_links(text) or [ln for ln in text.splitlines() if ln.lower().startswith(("vmess://","vless://","ss://"))]
            for l in links:
                proto, wl = classify_and_maybe_watermark(l, chance, tag, "🏳️")
                aggregated[country]["All"].add(wl)
                if proto:
                    aggregated[country][proto].add(wl)

        
        for url in full:
            logging.info("Fetching full: %s", url)
            text = await fetch_text(url, s)
            if not text or text == "RATE_LIMIT":
                logging.warning("Full fetch failed or limited: %s", url)
                continue
            links = find_links(text)
            for l in links:
                ip = extract_ip(l)
                country = await geolocate_ip(ip, s) if ip else None
                if not country:
                    country = "Unknown"
                proto, wl = classify_and_maybe_watermark(l, chance, tag, "🏳️")
                aggregated[country]["All"].add(wl)
                if proto:
                    aggregated[country][proto].add(wl)

    
    for c, d in aggregated.items():
        cname = "Unknown" if c.lower() in ("unknown", "🏴", "🏳️") else c
        with open(os.path.join(ALL_DIR, f"{cname}.txt"), "w", encoding="utf-8") as f:
            for x in sorted(d["All"]):
                f.write(x + "\n")
        for p in ("VLess", "VMess", "Shadowsocks"):
            with open(os.path.join(PROT_DIR, p, f"{cname}.txt"), "w", encoding="utf-8") as f:
                for x in sorted(d[p]):
                    f.write(x + "\n")
        logging.info("Wrote %s: %d links", cname, len(d["All"]))

    logging.info("Done! Total countries: %d", len(aggregated))

def main():
    with open(CONFIG_PATH, encoding="utf-8") as f:
        cfg = json.load(f)
    asyncio.run(process_all(cfg))

if __name__ == "__main__":
    main()
