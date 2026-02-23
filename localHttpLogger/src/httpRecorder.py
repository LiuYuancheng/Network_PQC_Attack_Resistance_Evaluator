#!/usr/bin/env python3
#!/usr/bin/env python3
#-----------------------------------------------------------------------------
# Name:        httpRequestLogger.py
#
# Purpose:     HTTP/HTTPS outgoing Request Monitor for Ubuntu Records ALL outbound 
#              HTTP/HTTPS requests, including those to non-existent domains.
#
# Author:      Yuancheng Liu
#
# Created:     2026/02/21
# Copyright:   
# License:     
#-----------------------------------------------------------------------------

"""
Workflow:
  - Sniffs raw packets on port 80 (HTTP) and 443 (HTTPS/TLS)
  - Extracts HTTP Host headers + method + path for clear-text HTTP
  - Extracts TLS SNI from ClientHello for HTTPS (no decryption needed)
  - Captures DNS queries (port 53) to record intent before TCP connects
  - Logs TCP SYN packets as a fallback for connections with no readable payload
  - Writes to both stdout and a rotating log file

REQUIREMENTS:
  sudo apt-get install python3-pip libpcap-dev tcpdump
  sudo pip3 install scapy --break-system-packages

"""

import argparse
import datetime
import json
import logging
import os
import re
import signal
import sys
import threading
from logging.handlers import RotatingFileHandler

# --------------------------------------------------------------------------- #
# Dependency check
# --------------------------------------------------------------------------- #
try:
    from scapy.all import (
        sniff, IP, IPv6, TCP, UDP, DNS, DNSQR,
        Raw, get_if_list,
    )
except ImportError:
    print("ERROR: scapy not installed.")
    print("Fix : sudo pip3 install scapy --break-system-packages")
    sys.exit(1)

import Log

#-----------------------------------------------------------------------------
print("Current working directory is : %s" % os.getcwd())
DIR_PATH = dirpath = os.path.dirname(os.path.abspath(__file__))
print("Current source code location : %s" % dirpath)
APP_NAME = ('httpRequestLogger', 'RequestOut')

TOP_DIR = 'src'

idx = dirpath.rfind(TOP_DIR)
gTopDir = dirpath[:idx + len(TOP_DIR)] if idx != -1 else dirpath   # found it - truncate right after TOPDIR
# Config the lib folder 

import Log
Log.initLogger(gTopDir, 'Logs', APP_NAME[0], APP_NAME[1], historyCnt=100, fPutLogsUnderDate=True)

DEBUG_FLG   = False
LOG_INFO    = 0
LOG_WARN    = 1
LOG_ERR     = 2
LOG_EXCEPT  = 3

# VARIABLES are the built in data type.
def gDebugPrint(msg, prt=True, logType=LOG_INFO):
    if prt: print(msg)
    if logType == LOG_WARN:
        Log.warning(msg)
    elif logType == LOG_ERR:
        Log.error(msg)
    elif logType == LOG_EXCEPT:
        Log.exception(msg)
    elif logType == LOG_INFO or DEBUG_FLG:
        Log.info(msg)

gCurrentNIC = None 

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #
DEFAULT_LOG_FILE = "./http_requests.log"
LOG_MAX_BYTES    = 10 * 1024 * 1024   # 10 MB
LOG_BACKUP_COUNT = 5

# --------------------------------------------------------------------------- #
# Globals (set in main)
# --------------------------------------------------------------------------- #
_logger    = None
_json_mode = False
_seen      = set()
_seen_lock = threading.Lock()

# --------------------------------------------------------------------------- #
# Event recorder  (deduplicates & formats)
# --------------------------------------------------------------------------- #
def record(etype: str, src: str, dst: str, dport: int, detail: str):
    key = f"{etype}|{src}|{dst}|{dport}|{detail}"
    with _seen_lock:
        if key in _seen:
            return
        _seen.add(key)
        if len(_seen) > 8000:
            _seen.clear()

    ts = datetime.datetime.now().isoformat(timespec="seconds")
    proto = {443: "HTTPS", 80: "HTTP", 0: "DNS"}.get(dport, str(dport))
    line  = f"[{ts}] [{etype:<10}] {proto:5} | {src} → {dst}:{dport} | {detail}"
    gDebugPrint(line)

# --------------------------------------------------------------------------- #
# DNS handler — captures intent even when TCP never succeeds
# --------------------------------------------------------------------------- #
def on_dns(pkt):
    try:
        if pkt[DNS].qr != 0 or not pkt.haslayer(DNSQR):
            return
        name = pkt[DNSQR].qname
        if isinstance(name, bytes):
            name = name.decode(errors="replace").rstrip(".")
        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        record("DNS_QUERY", str(src), "", 53, f"query={name}")
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# HTTP handler — plain-text on port 80
# --------------------------------------------------------------------------- #
_HTTP_RE  = re.compile(
    rb"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE) "
    rb"(\S+) HTTP/[\d.]+\r\n(.*?)\r\n\r\n",
    re.DOTALL,
)
_HOST_RE  = re.compile(rb"(?i)^Host:\s*(.+)$", re.MULTILINE)

def on_http(pkt):
    try:
        if not pkt.haslayer(Raw):
            return
        m = _HTTP_RE.match(bytes(pkt[Raw]))
        if not m:
            return
        method  = m.group(1).decode()
        path    = m.group(2).decode(errors="replace")
        hm      = _HOST_RE.search(m.group(3))
        host    = hm.group(1).decode(errors="replace").strip() if hm else ""
        src     = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst     = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
        url     = f"http://{host}{path}" if host else f"http://{dst}{path}"
        record("HTTP", str(src), str(dst), 80, f"{method} {url}")
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# TLS SNI extractor — no decryption; reads ClientHello only
# --------------------------------------------------------------------------- #
def _sni_from_client_hello(data: bytes):
    try:
        if len(data) < 5 or data[0] != 0x16:          # TLS handshake record
            return None
        rec_len   = int.from_bytes(data[3:5], "big")
        hs        = data[5:5 + rec_len]
        if not hs or hs[0] != 0x01:                   # ClientHello
            return None
        off = 1 + 3 + 2 + 32                           # type+len+version+random
        if len(hs) < off + 1:
            return None
        off += 1 + hs[off]                             # session id
        if len(hs) < off + 2:
            return None
        off += 2 + int.from_bytes(hs[off:off+2], "big")  # cipher suites
        if len(hs) < off + 1:
            return None
        off += 1 + hs[off]                             # compression methods
        if len(hs) < off + 2:
            return None
        ext_end = off + 2 + int.from_bytes(hs[off:off+2], "big")
        off    += 2
        while off + 4 <= ext_end:
            et   = int.from_bytes(hs[off:off+2], "big")
            el   = int.from_bytes(hs[off+2:off+4], "big")
            ed   = hs[off+4:off+4+el]
            off += 4 + el
            if et == 0:                                # server_name
                if len(ed) >= 5:
                    nl = int.from_bytes(ed[3:5], "big")
                    return ed[5:5+nl].decode(errors="replace")
    except Exception:
        pass
    return None

def on_https(pkt):
    try:
        if not pkt.haslayer(Raw):
            return
        sni = _sni_from_client_hello(bytes(pkt[Raw]))
        if not sni:
            return
        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
        record("HTTPS/TLS", str(src), str(dst), 443,
               f"SNI={sni}  url=https://{sni}/")
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# TCP SYN fallback — always logs the connection attempt
# --------------------------------------------------------------------------- #
def on_syn(pkt, port):
    try:
        tcp = pkt[TCP]
        if not (tcp.flags & 0x02) or (tcp.flags & 0x10):  # SYN but not SYN-ACK
            return
        src = pkt[IP].src if pkt.haslayer(IP) else pkt[IPv6].src
        dst = pkt[IP].dst if pkt.haslayer(IP) else pkt[IPv6].dst
        record("TCP_SYN", str(src), str(dst), port,
               f"connection attempt → {dst}:{port}")
    except Exception:
        pass

# --------------------------------------------------------------------------- #
# Master dispatcher
# --------------------------------------------------------------------------- #
def dispatcher(pkt):
    if pkt.haslayer(UDP) and pkt.haslayer(DNS):
        on_dns(pkt)
    elif pkt.haslayer(TCP):
        dport = pkt[TCP].dport
        if dport == 80:
            on_syn(pkt, 80)
            on_http(pkt)
        elif dport == 443:
            on_syn(pkt, 443)
            on_https(pkt)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def list_interfaces():
    """Print available network interfaces."""
    import subprocess
    result = subprocess.run(["tshark", "-D"], capture_output=True, text=True)
    gDebugPrint("Available interfaces:\n%s" %str(result.stdout or result.stderr))


#-----------------------------------------------------------------------------
def get_default_interface():
    """Try to find the default outbound interface."""
    try:
        import subprocess
        result = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True, text=True
        )
        for part in result.stdout.split():
            if part not in ("default", "via", "dev", "proto", "metric", "src"):
                if not part[0].isdigit():
                    return part
    except Exception:
        pass
    return "eth0"

# --------------------------------------------------------------------------- #
# --------------------------------------------------------------------------- #
def main():
    global gCurrentNIC
    gDebugPrint("Start the local http(s) request logger module.")

    signal.signal(signal.SIGINT,  lambda *_: (print("\n[*] Stopped."), sys.exit(0)))
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    list_interfaces()
    if gCurrentNIC is None: 
        gDebugPrint("[x] No network interface configured, try to use the 1st one as default.")
        gCurrentNIC = get_default_interface()
    gDebugPrint("Start to capture the http(s) request on interface: %s" % str(gCurrentNIC))

    bpf = "tcp port 80 or tcp port 443"
    bpf += " or udp port 53"
    sniff(iface=gCurrentNIC, filter=bpf, prn=dispatcher, store=False)

# --------------------------------------------------------------------------- #
if __name__ == "__main__":
    main()
