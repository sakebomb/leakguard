#!/usr/bin/env python3
"""Homelab network-map renderer for `leakguard map`. Emits Graphviz DOT from a
`leakguard scan --deep --json` dump. Render with: twopi -Tpng out.dot -o out.png"""
import re, ipaddress
from collections import defaultdict

def esc(s): return s.replace('"', '\\"')

SVC = [("AdGuard/DNS", r"adguard|pi-?hole|dns"), ("Reverse proxy", r"traefik|nginx|caddy|npm|cloudflared"),
       ("Home Assistant", r"homeassistant|hassio"), ("Nextcloud", r"nextcloud"),
       ("Media", r"jellyfin|plex|calibre|collabora"), ("Remote access", r"guacamole|rdp|vnc|ssh"),
       ("Notify", r"ntfy|gotify"), ("Bookmarks", r"karakeep|linkding"), ("Scanner", r"scanopy|scan"),
       ("Solar/energy", r"solaredge|inverter|shelly"), ("Ham radio", r"pi-?star|allstar"),
       ("NAS/storage", r"nas|truenas|synology|rdsg|storage"), ("Router/GW", r"gateway|router|freebox|repeteur")]
PALETTE = {"AdGuard/DNS":"#ffd33d","Reverse proxy":"#79c0ff","Home Assistant":"#7ee787","Nextcloud":"#79c0ff",
           "Media":"#d2a8ff","Remote access":"#ffa657","Notify":"#ffd33d","Bookmarks":"#a5d6ff","Scanner":"#ff7b72",
           "Solar/energy":"#f0e68c","Ham radio":"#f0883e","NAS/storage":"#ffa657","Router/GW":"#f0883e","host/service":"#c9d1d9"}
NAME_DEV = re.compile(r"-de-|^[a-z]+-s-|tab-|iphone|ipad|galaxy|-a1[0-9]", re.I)

def classify(host):
    for name, pat in SVC:
        if re.search(pat, host, re.I): return name
    return "host/service"

def emit_dot(data, out=print):
    user = data.get("user", "operator")
    hosts = sorted(set(list(data.get("ihosts", {})) + list(data.get("hosts", {}))))
    ips = list(data.get("ips", {}))
    tz = ", ".join(data.get("tz", {}))
    by_sub = defaultdict(list)
    for ip in ips:
        try: ipaddress.ip_address(ip)
        except Exception: continue
        sub = ".".join(ip.split(".")[:3]) + ".0/24"
        if not ip.endswith(".0"): by_sub[sub].append(ip)
        else: by_sub.setdefault(sub, [])
    out('graph homelab {')
    out('  layout="twopi"; root="op"; overlap=false; splines=true; bgcolor="#0d1117"; fontname="Helvetica";')
    out('  node [style=filled,fontcolor="#0d1117",color="#30363d",fontsize=11]; edge [color="#8b949e"];')
    out(f'  label="Homelab reconstructed from PUBLIC git commits of @{esc(user)}\\n'
        f'region {esc(tz)}  |  {len(hosts)} internal hostnames  |  {len(ips)} LAN addresses  |  {len(by_sub)} subnets\\n'
        f'nothing was probed - this is all in public git history"; labelloc="t"; fontsize=18; fontcolor="#e6edf3";')
    out(f'  op [label="@{esc(user)}\\nnamed human",shape=doublecircle,fillcolor="#f85149",fontcolor="white",fontsize=14];')
    for i, (sub, members) in enumerate(sorted(by_sub.items())):
        vlan = " (VLAN)" if sub.split(".")[2] not in ("1", "0") else ""
        out(f'  "sub{i}" [label="{esc(sub)}{vlan}\\n{len(set(members))} live hosts",shape=box3d,fillcolor="#58a6ff",fontcolor="white"];')
        out(f'  op -- "sub{i}" [penwidth=2,color="#58a6ff"];')
    for h in hosts:
        if NAME_DEV.search(h):
            out(f'  "{esc(h)}" [label="{esc(h)}\\n[personal device / name]",shape=note,fillcolor="#ff9bb3"];')
        else:
            cls = classify(h)
            out(f'  "{esc(h)}" [label="{esc(h)}\\n[{cls}]",shape=box,fillcolor="{PALETTE.get(cls,"#c9d1d9")}"];')
        out(f'  op -- "{esc(h)}";')
    out('}')
