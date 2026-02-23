#!/usr/bin/env python3
#-----------------------------------------------------------------------------
# Name:        httpRequestLogger.py
#
# Purpose:     Local HTTP/HTTPS Traffic Monitor using pyshark (tshark) : Captures 
#              outbound HTTP/HTTPS traffic from a network interface logs all the 
#              requests to a file.
#
# Author:      Yuancheng Liu
#
# Created:     2026/02/23
# Copyright:   
# License:     
#-----------------------------------------------------------------------------

"""
Requirements:
    sudo apt install tshark
    pip3 install pyshark

Notes:
    - HTTP (port 80) traffic is fully decoded: method, host, URI, headers.
    - HTTPS (port 443) traffic shows IP/port metadata only (TLS is encrypted).
      For full HTTPS decryption you would need the server's private key or
      use SSLKEYLOGFILE with a supporting application (see --keylog option).
    - Run as root (or add your user to the 'wireshark' group).
"""

import pyshark
import logging
import argparse
import sys
import os
import socket
import struct
import fcntl
import signal
from datetime import datetime

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

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def handle_packet(packet, logger: logging.Logger):
    """Called for every captured packet."""
    try:
        # Grab IP layer info
        src_ip  = packet.ip.src  if hasattr(packet, "ip") else "?"
        dst_ip  = packet.ip.dst  if hasattr(packet, "ip") else "?"
        proto   = packet.transport_layer or "?"

        src_port = "?"
        dst_port = "?"
        if hasattr(packet, "tcp"):
            src_port = packet.tcp.srcport
            dst_port = packet.tcp.dstport

        # ── HTTP (plain) ──────────────────────────────────────
        if hasattr(packet, "http"):
            http = packet.http

            # Only log requests (packets that have a request method)
            if hasattr(http, "request_method"):
                method   = getattr(http, "request_method",  "-")
                host     = getattr(http, "host",             "-")
                uri      = getattr(http, "request_uri",      "-")
                version  = getattr(http, "request_version",  "-")
                ua       = getattr(http, "user_agent",       "-")
                referer  = getattr(http, "referer",          "-")
                ct       = getattr(http, "content_type",     "-")

                url = f"http://{host}{uri}"
                gDebugPrint(
                    f"[HTTP  REQUEST ] {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                    f"{method} {url} {version} | "
                    f"User-Agent={ua} | Referer={referer} | Content-Type={ct}"
                )

            # Log HTTP responses (optional if we want ot get a possible C2 response)
            elif hasattr(http, "response_code"):
                status  = getattr(http, "response_code",    "-")
                phrase  = getattr(http, "response_phrase",  "-")
                ct      = getattr(http, "content_type",     "-")
                cl      = getattr(http, "content_length",   "-")
                gDebugPrint(
                    f"[HTTP  RESPONSE] {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                    f"{status} {phrase} | Content-Type={ct} | Content-Length={cl}"
                )

        # ── HTTPS / TLS ───────────────────────────────────────
        elif hasattr(packet, "tls"):
            tls = packet.tls

            # TLS Client Hello — contains SNI (Server Name Indication = the hostname)
            sni = None
            if hasattr(tls, "handshake_extensions_server_name"):
                sni = tls.handshake_extensions_server_name

            record_type = getattr(tls, "record_content_type", None)
            handshake   = getattr(tls, "handshake_type", None)

            # Only log outbound Client Hello (handshake type 1)
            if handshake == "1":
                gDebugPrint(
                    f"[HTTPS REQUEST ] {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                    f"TLS Client Hello | SNI={sni or 'N/A'}"
                )
            elif dst_port == "443" and not handshake:
                # Encrypted application data — log minimally
                size = getattr(packet, "length", "-")
                gDebugPrint(
                    f"[HTTPS DATA    ] {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                    f"Encrypted | Size={size} bytes"
                )

        # ── Plain TCP SYN to port 80/443 (fallback if no layer decoded) ──
        elif hasattr(packet, "tcp"):
            tcp = packet.tcp
            if hasattr(tcp, "flags_syn") and tcp.flags_syn == "1" and not getattr(tcp, "flags_ack", "0") == "1":
                if dst_port in ("80", "443"):
                    scheme = "https" if dst_port == "443" else "http"
                    gDebugPrint(
                        f"[TCP   SYN     ] {src_ip}:{src_port} → {dst_ip}:{dst_port} | "
                        f"New {scheme.upper()} connection initiated"
                    )

    except AttributeError:
        pass  # Incomplete / malformed packet
    except Exception as e:
        gDebugPrint(f"[WARN] Packet parse error: {e}", logType=LOG_ERR)

#-----------------------------------------------------------------------------
# Main capture loop
#-----------------------------------------------------------------------------
def start_capture():
    global gCurrentNIC
    """Start live capture on the given interface."""
    # BPF filter: only HTTP (80) and HTTPS (443) TCP traffic
    bpf_filter = "tcp port 80 or tcp port 443"
    override_prefs = {}
    capture = pyshark.LiveCapture(
        interface=gCurrentNIC,
        bpf_filter=bpf_filter,
        override_prefs=override_prefs,
        display_filter="http or tls",   # decode-level filter
        use_json=True,
        include_raw=False,
    )
    def stop(sig, frame):
        gDebugPrint("\nCapture stopped by user.")
        capture.close()
        sys.exit(0)

    signal.signal(signal.SIGINT,  stop)
    signal.signal(signal.SIGTERM, stop)
    try:
        for packet in capture.sniff_continuously():
            handle_packet(packet, logger)
    except Exception as e:
        if "closed" not in str(e).lower():
            gDebugPrint(f"Capture error: {e}", logType=LOG_ERR)

#-----------------------------------------------------------------------------
#-----------------------------------------------------------------------------
def main():
    global gCurrentNIC
    gDebugPrint("Start the local http(s) request logger module.")
    list_interfaces()
    if gCurrentNIC is None: 
        gDebugPrint("[x] No network interface configured, try to use the 1st one as default.")
        gCurrentNIC = get_default_interface()
    gDebugPrint("Start to capture the http(s) request on interface: %s" % str(gCurrentNIC))
    start_capture()

#-----------------------------------------------------------------------------
if __name__ == "__main__":
    main()
