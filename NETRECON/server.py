import os
import sys
import time
import socket
import subprocess
import ipaddress
import threading
import platform
import psutil
from flask import Flask, jsonify, render_template
from flask_cors import CORS

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

app = Flask(__name__)
CORS(app)

IS_WINDOWS = platform.system() == "Windows"

_scan_results = []
_scan_status  = "idle"
_scan_started = None
_scan_lock    = threading.Lock()

OUI_TABLE = {
    "00:00:0C": "Cisco",
    "00:1A:2B": "Cisco",
    "00:50:56": "VMware",
    "00:0C:29": "VMware",
    "00:15:5D": "Microsoft Hyper-V",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi",
    "00:1B:21": "Intel",
    "8C:8D:28": "Intel",
    "A4:C3:F0": "Intel",
    "00:1E:65": "Intel",
    "F0:18:98": "Apple",
    "AC:87:A3": "Apple",
    "3C:15:C2": "Apple",
    "A8:51:AB": "Apple",
    "00:23:DF": "Apple",
    "00:26:08": "Apple",
    "34:36:3B": "Apple",
    "7C:D1:C3": "Apple",
    "48:60:BC": "Apple",
    "00:17:F2": "Apple",
    "F4:F1:5A": "Google",
    "54:60:09": "Google",
    "F4:F5:D8": "Google",
    "94:EB:2C": "Google",
    "00:1A:11": "Google",
    "18:FE:34": "Espressif (ESP)",
    "24:6F:28": "Espressif (ESP)",
    "A4:CF:12": "Espressif (ESP)",
    "30:AE:A4": "Espressif (ESP)",
    "84:0D:8E": "Espressif (ESP)",
    "00:11:32": "Synology",
    "00:13:6C": "Samsung",
    "78:BD:BC": "Samsung",
    "F4:7B:5E": "Samsung",
    "00:1F:CC": "Samsung",
    "2C:44:01": "Samsung",
    "34:14:5F": "Samsung",
    "70:F9:27": "Samsung",
    "94:35:0A": "Samsung",
    "A0:21:B7": "Samsung",
    "B0:EC:71": "Samsung",
    "F8:04:2E": "Samsung",
    "28:6C:07": "Amazon",
    "FC:A6:67": "Amazon",
    "40:B4:CD": "Amazon",
    "74:75:48": "Amazon",
    "10:AE:60": "Amazon",
    "84:D6:D0": "Amazon",
    "00:17:88": "Philips Hue",
    "EC:B5:FA": "Philips Hue",
    "00:0D:3A": "Microsoft",
    "28:18:78": "Microsoft",
    "C4:9D:ED": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:AF:97": "TP-Link",
    "60:32:B1": "TP-Link",
    "98:DE:D0": "TP-Link",
    "B0:BE:76": "TP-Link",
    "F4:EC:38": "TP-Link",
    "FC:EC:DA": "TP-Link",
    "AC:84:C6": "TP-Link",
    "30:DE:4B": "TP-Link",
    "00:0C:42": "Mikrotik",
    "CC:2D:E0": "Mikrotik",
    "18:65:90": "Xiaomi",
    "64:09:80": "Xiaomi",
    "AC:F7:F3": "Xiaomi",
    "00:23:14": "ASUS",
    "04:92:26": "ASUS",
    "10:C3:7B": "ASUS",
    "2C:FD:A1": "ASUS",
    "74:D0:2B": "ASUS",
    "AC:9E:17": "ASUS",
    "50:46:5D": "ASUS",
    "08:62:66": "ASUS",
    "00:E0:4C": "Realtek",
    "00:26:18": "Netgear",
    "C0:FF:D4": "Netgear",
    "20:4E:7F": "Netgear",
    "84:1B:5E": "Netgear",
    "A0:04:60": "Netgear",
    "00:09:5B": "Netgear",
    "00:1D:7E": "Linksys",
    "00:23:69": "Linksys",
    "C8:D3:A3": "Linksys",
    "00:90:4C": "Epson",
    "00:26:AB": "Epson",
    "10:1F:74": "Dell",
    "14:18:77": "Dell",
    "18:66:DA": "Dell",
    "B0:83:FE": "Dell",
    "F8:DB:88": "Dell",
    "F4:8E:38": "Dell",
    "00:24:E8": "Dell",
    "00:1B:77": "Lenovo",
    "48:AD:08": "Lenovo",
    "54:EE:75": "Lenovo",
    "98:FA:9B": "Lenovo",
    "E8:2A:EA": "Lenovo",
    "9C:2A:83": "Lenovo",
    "00:1A:6B": "HP",
    "3C:D9:2B": "HP",
    "9C:8E:99": "HP",
    "C8:CB:9E": "HP",
    "18:A9:05": "HP",
    "10:60:4B": "HP",
    "D0:BF:9C": "HP",
}


def lookup_vendor(mac):
    prefix = mac.upper().replace("-", ":")[:8]
    return OUI_TABLE.get(prefix, "Unknown")


def is_admin():
    if IS_WINDOWS:
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.geteuid() == 0


def get_local_networks():
    networks = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == "AF_INET" and not addr.address.startswith("127."):
                try:
                    net = ipaddress.IPv4Network(
                        "{}/20".format(addr.address, addr.netmask),
                        strict=False
                    )
                    if net.prefixlen >= 20:
                        networks.append((iface, str(net)))
                except Exception:
                    pass
    return networks


def get_my_ips():
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family.name == "AF_INET":
                ips.add(addr.address)
    return ips


def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ip


def read_arp_cache():
    devices = []

    if IS_WINDOWS:
        try:
            result = subprocess.run(
                ["arp", "-a"],
                capture_output=True,
                text=True,
                timeout=10
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2].lower() == "dynamic":
                    ip  = parts[0]
                    mac = parts[1].upper().replace("-", ":")
                    if ip and mac and mac != "FF:FF:FF:FF:FF:FF":
                        devices.append({"ip": ip, "mac": mac})
        except Exception:
            pass

    else:
        try:
            with open("/proc/net/arp") as f:
                lines = f.readlines()[1:] 
            for line in lines:
                parts = line.split()
                if len(parts) >= 4 and parts[2] == "0x2":
                    ip  = parts[0]
                    mac = parts[3].upper()
                    if mac != "00:00:00:00:00:00":
                        devices.append({"ip": ip, "mac": mac})
        except Exception:
            pass

    return devices


def arp_scan(network_cidr, iface):
    try:
        arp_request = ARP(pdst=network_cidr)
        broadcast   = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet      = broadcast / arp_request

        answered, _ = srp(packet, iface=iface, timeout=2, verbose=False)

        results = []
        for sent, received in answered:
            results.append({
                "ip":  received.psrc,
                "mac": received.hwsrc.upper(),
            })
        return results
    except Exception:
        return []


def full_scan():
    global _scan_results, _scan_status, _scan_started

    with _scan_lock:
        _scan_status  = "scanning"
        _scan_started = time.time()

    try:
        discovered = {} 
        networks = get_local_networks()
        for iface, cidr in networks:
            for dev in arp_scan(cidr, iface):
                discovered[dev["mac"]] = {
                    "ip":     dev["ip"],
                    "mac":    dev["mac"],
                    "source": "arp-scan",
                    "iface":  iface,
                }
        for dev in read_arp_cache():
            if dev["mac"] not in discovered:
                discovered[dev["mac"]] = {
                    "ip":     dev["ip"],
                    "mac":    dev["mac"],
                    "source": "arp-cache",
                    "iface":  "-",
                }
        my_ips  = get_my_ips()
        results = []
        for mac, dev in discovered.items():
            is_self = dev["ip"] in my_ips
            results.append({
                "ip":         dev["ip"],
                "mac":        dev["mac"],
                "vendor":     lookup_vendor(dev["mac"]),
                "hostname":   resolve_hostname(dev["ip"]),
                "iface":      dev.get("iface", "-"),
                "source":     dev.get("source", "unknown"),
                "is_self":    is_self,
                "status":     "this device" if is_self else "online",
                "scanned_at": time.strftime("%H:%M:%S"),
            })
        results.sort(key=lambda x: (
            not x["is_self"],
            [int(p) for p in x["ip"].split(".")]
        ))

        with _scan_lock:
            _scan_results = results
            _scan_status  = "done"

    except Exception as e:
        with _scan_lock:
            _scan_status = "error: {}".format(str(e))


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def start_scan():
    global _scan_status
    if _scan_status == "scanning":
        return jsonify({"message": "Scan already running"}), 409
    thread = threading.Thread(target=full_scan, daemon=True)
    thread.start()
    return jsonify({"message": "Scan started"})


@app.route("/api/status")
def scan_status():
    elapsed = round(time.time() - _scan_started, 1) if _scan_started else 0
    return jsonify({
        "status":  _scan_status,
        "count":   len(_scan_results),
        "elapsed": elapsed,
        "devices": _scan_results,
    })


@app.route("/api/myinfo")
def my_info():
    hostname = socket.gethostname()
    my_ips   = list(get_my_ips() - {"127.0.0.1"})
    networks = get_local_networks()
    return jsonify({
        "hostname": hostname,
        "ips":      my_ips,
        "networks": [{"iface": i, "cidr": c} for i, c in networks],
        "is_admin": is_admin(),
        "platform": platform.system(),
    })


if __name__ == "__main__":
    if not is_admin():
        print("")
        print("  WARNING: Not running as Administrator/root.")
        if IS_WINDOWS:
            print("  For a full ARP scan, right-click your terminal")
            print("  and choose 'Run as Administrator', then rerun.")
        else:
            print("  For a full ARP scan, run: sudo python server.py")
        print("  Passive ARP cache scan will still work without it.")
        print("")
    else:
        print("")
        print("  Running with admin privileges - full ARP scan enabled.")
        print("")

    print("  WiFi Tracker running at  http://127.0.0.1:5000")
    print("")
    app.run(debug=False, port=5000)