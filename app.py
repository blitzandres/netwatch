import collections
import ipaddress
import json
import os
import re
import shlex
import shutil
import signal
import socket
import ssl
import subprocess
import threading
import time
from datetime import datetime
from urllib.parse import quote
from urllib.request import urlopen

import psutil
from flask import Flask, jsonify, request, send_from_directory


APP_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(APP_DIR, "static")
LOG_DIR = os.path.expanduser("~/netwatch_logs")
HOST = os.environ.get("NETWATCH_BIND", "127.0.0.1")
PORT = int(os.environ.get("NETWATCH_PORT", "5001"))
SERVER_NAME = "NetWatch Next Core"
PACKET_LIMIT = 800
BANDWIDTH_LIMIT = 240
GEO_TIMEOUT = 4
SAFE_CMD_TIMEOUT = 20
TRACEROUTE_TIMEOUT = 25

app = Flask(__name__, static_folder=STATIC_DIR, static_url_path="/static")


state_lock = threading.Lock()
packet_lock = threading.Lock()
bandwidth_lock = threading.Lock()
geo_lock = threading.Lock()

packet_log = collections.deque(maxlen=PACKET_LIMIT)
bandwidth_samples = collections.deque(maxlen=BANDWIDTH_LIMIT)
geo_cache = {}
capture_process = None
capture_thread_started = False
bandwidth_thread_started = False
status_started_at = time.time()


def now_iso():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def now_clock():
    return datetime.now().strftime("%H:%M:%S")


def command_exists(name):
    return shutil.which(name) is not None


def is_root():
    return os.geteuid() == 0


def default_interface():
    try:
        out = subprocess.run(
            ["route", "get", "default"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        match = re.search(r"interface:\s+(\S+)", out.stdout)
        if match:
            return match.group(1)
    except Exception:
        pass

    for name, addrs in psutil.net_if_addrs().items():
        if name.startswith("lo"):
            continue
        if any(a.family == socket.AF_INET for a in addrs):
            return name
    return "en0"


def local_ipv4(interface_name):
    try:
        for addr in psutil.net_if_addrs().get(interface_name, []):
            if addr.family == socket.AF_INET:
                return addr.address
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def fetch_public_ip():
    candidates = [
        "https://api.ipify.org",
        "https://ifconfig.me/ip",
    ]
    for url in candidates:
        try:
            with urlopen(url, timeout=3) as handle:
                value = handle.read().decode("utf-8", "ignore").strip()
                if value:
                    return value
        except Exception:
            continue
    return ""


INTERFACE = default_interface()
LOCAL_IP = local_ipv4(INTERFACE)
PUBLIC_IP = fetch_public_ip()


def safe_origin_geo():
    geo = {
        "lat": 0.0,
        "lng": 0.0,
        "city": "Origin",
        "country": "Local",
        "isp": "This Mac",
    }
    if PUBLIC_IP:
        looked_up = geo_lookup(PUBLIC_IP)
        if looked_up.get("lat") is not None and looked_up.get("lng") is not None:
            geo.update(looked_up)
    return geo


def ensure_log_dir():
    os.makedirs(LOG_DIR, exist_ok=True)


def safe_realpath(path):
    return os.path.realpath(os.path.abspath(os.path.expanduser(path)))


def path_within(path, root):
    try:
        return os.path.commonpath([safe_realpath(path), safe_realpath(root)]) == safe_realpath(root)
    except Exception:
        return False


def is_private_ip(value):
    try:
        ip = ipaddress.ip_address(value)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
    except Exception:
        return True


def resolve_host(value):
    value = (value or "").strip()
    if not value:
        return ""
    try:
        ipaddress.ip_address(value)
        return value
    except Exception:
        pass
    try:
        return socket.gethostbyname(value)
    except Exception:
        return ""


def geo_lookup(target):
    ip = resolve_host(target)
    if not ip:
        return {}

    with geo_lock:
        if ip in geo_cache:
            return dict(geo_cache[ip])

    if is_private_ip(ip):
        if ip in {LOCAL_IP, PUBLIC_IP, "127.0.0.1"}:
            local_geo = {
                "lat": 0.0,
                "lng": 0.0,
                "city": "Local",
                "country": "Local",
                "isp": "This Mac",
                "query": ip,
            }
            with geo_lock:
                geo_cache[ip] = local_geo
            return dict(local_geo)
        return {}

    try:
        url = (
            "http://ip-api.com/json/"
            + quote(ip)
            + "?fields=status,query,lat,lon,country,city,isp,org,as"
        )
        with urlopen(url, timeout=GEO_TIMEOUT) as handle:
            payload = json.loads(handle.read().decode("utf-8", "ignore"))
        if payload.get("status") == "success":
            result = {
                "lat": payload.get("lat"),
                "lng": payload.get("lon"),
                "country": payload.get("country") or "",
                "city": payload.get("city") or "",
                "isp": payload.get("org") or payload.get("isp") or "",
                "as": payload.get("as") or "",
                "query": payload.get("query") or ip,
            }
        else:
            result = {}
    except Exception:
        result = {}

    with geo_lock:
        geo_cache[ip] = dict(result)
    return dict(result)


ORIGIN_GEO = safe_origin_geo()


def detect_proto(line, src_port, dst_port):
    lowered = line.lower()
    if "udp" in lowered:
        return "UDP"
    if "icmp" in lowered:
        return "ICMP"
    if src_port == 443 or dst_port == 443:
        return "TLS"
    if src_port == 53 or dst_port == 53:
        return "DNS"
    return "TCP"


def classify_direction(src_ip, dst_ip):
    if src_ip == LOCAL_IP or src_ip == "127.0.0.1":
        return "OUT", dst_ip
    if dst_ip == LOCAL_IP or dst_ip == "127.0.0.1":
        return "IN", src_ip
    if is_private_ip(src_ip) and not is_private_ip(dst_ip):
        return "OUT", dst_ip
    if not is_private_ip(src_ip) and is_private_ip(dst_ip):
        return "IN", src_ip
    return "OUT", dst_ip


def parse_tcpdump_line(line):
    line = line.strip()
    if not line or " IP " not in line:
        return None

    match = re.search(
        r"IP\s+(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?\s+>\s+(\d+\.\d+\.\d+\.\d+)(?:\.(\d+))?:.*length\s+(\d+)",
        line,
    )
    if not match:
        return None

    src_ip, src_port, dst_ip, dst_port, length = match.groups()
    src_port = int(src_port or 0)
    dst_port = int(dst_port or 0)
    length = int(length or 0)
    direction, remote_ip = classify_direction(src_ip, dst_ip)
    return {
        "ts": now_clock(),
        "src": src_ip,
        "dst": dst_ip,
        "sp": src_port,
        "dp": dst_port,
        "proto": detect_proto(line, src_port, dst_port),
        "len": length,
        "dir": direction,
        "remote_ip": remote_ip,
    }


def capture_worker():
    global capture_process

    def run():
        global capture_process
        if not is_root() or not command_exists("tcpdump"):
            return

        command = [
            "tcpdump",
            "-l",
            "-nn",
            "-tt",
            "-q",
            "-i",
            INTERFACE,
            "ip",
        ]
        try:
            capture_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1,
            )
            assert capture_process.stdout is not None
            for line in capture_process.stdout:
                parsed = parse_tcpdump_line(line)
                if not parsed:
                    continue
                with packet_lock:
                    packet_log.appendleft(parsed)
        except Exception:
            capture_process = None

    threading.Thread(target=run, daemon=True).start()


def bandwidth_worker():
    def run():
        prev = psutil.net_io_counters()
        while True:
            time.sleep(1)
            try:
                curr = psutil.net_io_counters()
                sent = max(0.0, (curr.bytes_sent - prev.bytes_sent) / 1024.0)
                recv = max(0.0, (curr.bytes_recv - prev.bytes_recv) / 1024.0)
                prev = curr
                sample = {
                    "ts": now_clock(),
                    "sent": round(sent, 2),
                    "recv": round(recv, 2),
                }
                with bandwidth_lock:
                    bandwidth_samples.append(sample)
            except Exception:
                continue

    threading.Thread(target=run, daemon=True).start()


def ensure_workers():
    global capture_thread_started, bandwidth_thread_started
    if not capture_thread_started:
        capture_thread_started = True
        capture_worker()
    if not bandwidth_thread_started:
        bandwidth_thread_started = True
        bandwidth_worker()


def snapshot_packets():
    with packet_lock:
        packets = list(packet_log)
    return packets


def snapshot_connections():
    proc_names = {}
    try:
        proc_names = {
            p.info["pid"]: (p.info["name"] or "?")
            for p in psutil.process_iter(["pid", "name"])
        }
    except Exception:
        proc_names = {}

    rows = []
    seen = set()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if not conn.raddr:
                continue
            remote_ip = getattr(conn.raddr, "ip", None) or conn.raddr[0]
            remote_port = getattr(conn.raddr, "port", None) or conn.raddr[1]
            if not remote_ip:
                continue
            key = (conn.pid, remote_ip, remote_port, conn.status)
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "proc": proc_names.get(conn.pid, "?"),
                    "raddr": f"{remote_ip}:{remote_port}",
                    "status": conn.status or "UNKNOWN",
                    "pid": conn.pid,
                    "co": "",
                }
            )
    except Exception:
        return []

    status_rank = {
        "ESTABLISHED": 0,
        "SYN_SENT": 1,
        "CLOSE_WAIT": 2,
        "TIME_WAIT": 3,
        "LISTEN": 4,
    }
    rows.sort(key=lambda row: (status_rank.get(row["status"], 9), row["proc"], row["raddr"]))
    return rows[:80]


def live_entries_from_connections():
    aggregate = {}
    for row in snapshot_connections():
        raw = row["raddr"].split(":", 1)[0]
        if is_private_ip(raw):
            continue
        item = aggregate.setdefault(
            raw,
            {
                "ip": raw,
                "bytes": 0,
                "out_bytes": 0,
                "in_bytes": 0,
                "hits": 0,
                "proc": row["proc"],
                "status": row["status"],
            },
        )
        item["bytes"] += 65536
        item["out_bytes"] += 65536
        item["hits"] += 1
    return list(aggregate.values())


def live_entries_from_packets():
    aggregate = {}
    for pkt in snapshot_packets():
        remote_ip = pkt.get("remote_ip")
        if not remote_ip or is_private_ip(remote_ip):
            continue
        item = aggregate.setdefault(
            remote_ip,
            {
                "ip": remote_ip,
                "bytes": 0,
                "out_bytes": 0,
                "in_bytes": 0,
                "hits": 0,
                "last_proto": pkt.get("proto") or "",
                "last_port": pkt.get("dp") or pkt.get("sp") or 0,
            },
        )
        item["bytes"] += pkt.get("len", 0)
        if pkt.get("dir") == "OUT":
            item["out_bytes"] += pkt.get("len", 0)
        else:
            item["in_bytes"] += pkt.get("len", 0)
        item["hits"] += 1
    return list(aggregate.values())


def enrich_live_entries(entries, limit=60):
    enriched = []
    for entry in sorted(entries, key=lambda item: item.get("bytes", 0), reverse=True)[:limit]:
        geo = geo_lookup(entry["ip"])
        if geo.get("lat") is None or geo.get("lng") is None:
            continue
        merged = dict(entry)
        merged.update(geo)
        merged["company"] = geo.get("isp") or entry.get("proc") or entry["ip"]
        merged["country"] = geo.get("country") or ""
        merged["city"] = geo.get("city") or ""
        merged["threat"] = entry.get("last_port") in {23, 3389, 445, 5900}
        enriched.append(merged)
    return enriched


def build_traffic_map():
    origin = dict(ORIGIN_GEO)
    entries = live_entries_from_packets()
    if not entries:
        entries = live_entries_from_connections()
    markers = enrich_live_entries(entries)
    arcs = []
    for marker in markers:
        outbound = marker.get("out_bytes", 0) >= marker.get("in_bytes", 0)
        if outbound:
            start = [origin.get("lat", 0.0), origin.get("lng", 0.0)]
            end = [marker.get("lat"), marker.get("lng")]
            direction = "OUT"
        else:
            start = [marker.get("lat"), marker.get("lng")]
            end = [origin.get("lat", 0.0), origin.get("lng", 0.0)]
            direction = "IN"
        arcs.append(
            {
                "from": start,
                "to": end,
                "bytes": marker.get("bytes", 0),
                "direction": direction,
                "threat": marker.get("threat", False),
                "ip": marker.get("ip"),
                "company": marker.get("company"),
            }
        )
    return {
        "origin": origin,
        "origin_ip": PUBLIC_IP or LOCAL_IP,
        "markers": markers,
        "arcs": arcs,
    }


def human_size(num_bytes):
    value = float(num_bytes)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024.0
    return f"{value:.1f} TB"


def folder_size(path, cap=2500):
    real = safe_realpath(path)
    if not os.path.exists(real):
        return 0
    if os.path.isfile(real):
        try:
            return os.path.getsize(real)
        except Exception:
            return 0

    total = 0
    seen = 0
    for root, _, files in os.walk(real):
        for name in files:
            seen += 1
            if seen > cap:
                return total
            full = os.path.join(root, name)
            try:
                total += os.path.getsize(full)
            except Exception:
                continue
    return total


def folder_rows():
    ensure_log_dir()
    items = [
        ("NetWatch App", APP_DIR),
        ("NetWatch Logs", LOG_DIR),
        ("Downloads", "~/Downloads"),
        ("Documents", "~/Documents"),
        ("Desktop", "~/Desktop"),
    ]
    rows = []
    for label, path in items:
        full = safe_realpath(path)
        exists = os.path.exists(full)
        rows.append(
            {
                "label": label,
                "path": full,
                "size": human_size(folder_size(full)) if exists else "0 B",
                "exists": exists,
            }
        )
    return rows


SAFE_COMMANDS = {
    "arp",
    "curl",
    "dig",
    "host",
    "ifconfig",
    "ipconfig",
    "lsof",
    "netstat",
    "nslookup",
    "ping",
    "traceroute",
    "whois",
}


def validate_run_command(parts):
    if not parts:
        return False, "No command supplied."
    base = parts[0]
    if base not in SAFE_COMMANDS:
        allowed = ", ".join(sorted(SAFE_COMMANDS))
        return False, f"Command not allowed. Only safe read-only commands: {allowed}"
    if not command_exists(base):
        return False, f"{base} is not installed on this Mac."

    blocked_fragments = {";", "&&", "||", "|", ">", "<", "$(", "`"}
    for arg in parts[1:]:
        if any(fragment in arg for fragment in blocked_fragments):
            return False, "Shell operators are not allowed."

    if base == "curl":
        for arg in parts[1:]:
            lowered = arg.lower()
            if lowered.startswith("file:"):
                return False, "curl file:// access is blocked."
            if lowered.startswith("/") or lowered.startswith("~"):
                return False, "Local file paths are not allowed."
        urls = [arg for arg in parts[1:] if "://" in arg]
        if urls and not all(url.lower().startswith(("http://", "https://")) for url in urls):
            return False, "Only http:// and https:// URLs are allowed."
        if any(arg in {"-o", "--output", "--upload-file", "-T"} for arg in parts[1:]):
            return False, "curl output and upload flags are blocked."
    return True, ""


def run_command(parts, timeout=SAFE_CMD_TIMEOUT):
    completed = subprocess.run(
        parts,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return {
        "out": completed.stdout[:6000],
        "err": completed.stderr[:2000],
    }


def list_device_adapters():
    adapters = [
        {
            "key": "adb",
            "label": "Android / ADB",
            "hint": "Android phones, Android TV, Fire TV, emulators",
            "tools": ["adb"],
        },
        {
            "key": "webos",
            "label": "LG webOS",
            "hint": "LG TVs and other webOS devices",
            "tools": ["ares-novacom", "ares-setup-device"],
        },
        {
            "key": "tizen",
            "label": "Samsung / Tizen",
            "hint": "Samsung TVs and smart displays",
            "tools": ["sdb", "tizen"],
        },
    ]
    rows = []
    available_count = 0
    for adapter in adapters:
        tools = [{"name": tool, "available": command_exists(tool)} for tool in adapter["tools"]]
        available = any(tool["available"] for tool in tools)
        if available:
            available_count += 1
        rows.append(
            {
                "key": adapter["key"],
                "label": adapter["label"],
                "hint": adapter["hint"],
                "available": available,
                "tools": tools,
            }
        )
    return {
        "adapters": rows,
        "summary": {
            "total": len(rows),
            "available": available_count,
            "missing": len(rows) - available_count,
        },
    }


def process_rows():
    conn_counts = collections.Counter()
    try:
        for conn in psutil.net_connections(kind="inet"):
            if conn.pid:
                conn_counts[conn.pid] += 1
    except Exception:
        conn_counts = collections.Counter()

    total_mem = psutil.virtual_memory().total
    rows = []
    for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
        try:
            info = proc.info
            memory_info = info.get("memory_info")
            rss = memory_info.rss if memory_info else 0
            mem_mb = round(rss / 1048576, 1)
            net_conns = conn_counts.get(info["pid"], 0)
            if mem_mb < 0.5 and net_conns == 0:
                continue
            rows.append(
                {
                    "pid": info["pid"],
                    "name": info.get("name") or "?",
                    "mem_mb": mem_mb,
                    "mem_pct": round((rss / total_mem) * 100, 1) if total_mem else 0,
                    "cpu": info.get("cpu_percent") or 0,
                    "net_conns": net_conns,
                    "status": info.get("status") or "unknown",
                }
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    rows.sort(key=lambda row: (row["net_conns"], row["mem_mb"]), reverse=True)
    vm = psutil.virtual_memory()
    return {
        "processes": rows[:40],
        "total_gb": round(vm.total / 1073741824, 2),
        "used_gb": round(vm.used / 1073741824, 2),
        "free_gb": round(vm.available / 1073741824, 2),
        "pct": vm.percent,
    }


def probe_geo(target):
    ip = resolve_host(target)
    if not ip:
        return {"error": "target could not be resolved"}
    geo = geo_lookup(ip)
    if not geo:
        return {"error": "no geo data", "query": ip}
    return {
        "query": ip,
        "lat": geo.get("lat"),
        "lon": geo.get("lng"),
        "country": geo.get("country"),
        "city": geo.get("city"),
        "isp": geo.get("isp"),
        "as": geo.get("as"),
    }


def probe_ping(target):
    if not command_exists("ping"):
        return {"alive": False, "error": "ping not installed"}
    try:
        result = subprocess.run(
            ["ping", "-c", "3", target],
            capture_output=True,
            text=True,
            timeout=8,
        )
        stdout = result.stdout
        round_trip = re.search(r"min/avg/max(?:/stddev)?\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)", stdout)
        loss = re.search(r"(\d+(?:\.\d+)?)% packet loss", stdout)
        return {
            "alive": result.returncode == 0,
            "min_ms": float(round_trip.group(1)) if round_trip else None,
            "avg_ms": float(round_trip.group(2)) if round_trip else None,
            "max_ms": float(round_trip.group(3)) if round_trip else None,
            "loss_pct": float(loss.group(1)) if loss else None,
        }
    except Exception as exc:
        return {"alive": False, "error": str(exc)}


def probe_ports(target):
    ports = [22, 53, 80, 123, 443, 445, 8080, 8443, 3389, 5900]
    names = {
        22: "SSH",
        53: "DNS",
        80: "HTTP",
        123: "NTP",
        443: "HTTPS",
        445: "SMB",
        8080: "HTTP Alt",
        8443: "HTTPS Alt",
        3389: "RDP",
        5900: "VNC",
    }
    rows = []
    host = resolve_host(target) or target
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.35)
        try:
            if sock.connect_ex((host, port)) == 0:
                rows.append({"port": port, "service": names.get(port, "?")})
        except Exception:
            pass
        finally:
            sock.close()
    return rows


def probe_ssl(target):
    host = target.strip()
    if not host:
        return {"ok": False, "error": "target required"}
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_OPTIONAL
        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                cert = secure.getpeercert()
        subject = dict(item[0] for item in cert.get("subject", []))
        issuer = dict(item[0] for item in cert.get("issuer", []))
        not_after = cert.get("notAfter", "")
        days_left = None
        if not_after:
            try:
                expiry = ssl.cert_time_to_seconds(not_after)
                days_left = int((expiry - time.time()) / 86400)
            except Exception:
                days_left = None
        return {
            "ok": True,
            "subject_cn": subject.get("commonName", "?"),
            "issuer_o": issuer.get("organizationName", "?"),
            "days_left": days_left,
            "expired": bool(days_left is not None and days_left < 0),
            "grade": "A" if days_left is None or days_left > 30 else "C" if days_left >= 0 else "F",
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def probe_dns(target):
    rows = {}
    if command_exists("dig"):
        for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
            try:
                result = subprocess.run(
                    ["dig", "+short", "+time=2", target, record_type],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                values = [line.strip() for line in result.stdout.splitlines() if line.strip()]
                if values:
                    rows[record_type] = values[:5]
            except Exception:
                continue
    if not rows:
        ip = resolve_host(target)
        if ip:
            rows["A"] = [ip]
    return rows


def probe_whois(target):
    if not command_exists("whois"):
        return {"error": "whois not installed", "lines": []}
    try:
        result = subprocess.run(
            ["whois", target],
            capture_output=True,
            text=True,
            timeout=10,
        )
        lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip() and not line.startswith("%") and not line.startswith("#")
        ]
        interesting = [
            line
            for line in lines
            if any(
                key in line.lower()
                for key in [
                    "registrar",
                    "created",
                    "updated",
                    "expire",
                    "country",
                    "org",
                    "netname",
                    "name server",
                    "abuse",
                ]
            )
        ]
        return {"lines": interesting[:14], "raw_length": len(result.stdout)}
    except Exception as exc:
        return {"error": str(exc), "lines": []}


def probe_bgp(target):
    try:
        url = "https://api.hackertarget.com/aslookup/?q=" + quote(target)
        with urlopen(url, timeout=5) as handle:
            raw = handle.read().decode("utf-8", "ignore").strip()
        return {"raw": raw[:300]}
    except Exception as exc:
        return {"raw": "", "error": str(exc)}


def traceroute_hops(target):
    if not command_exists("traceroute"):
        return {"target": target, "hops": [], "raw": "traceroute not installed"}
    try:
        result = subprocess.run(
            ["traceroute", "-n", "-q", "1", "-m", "12", "-w", "1", target],
            capture_output=True,
            text=True,
            timeout=TRACEROUTE_TIMEOUT,
        )
        hops = []
        for line in result.stdout.splitlines()[1:]:
            parts = line.strip().split()
            if not parts:
                continue
            try:
                hop_no = int(parts[0])
            except Exception:
                continue
            if len(parts) > 1 and parts[1] == "*":
                hops.append({"hop": hop_no, "ip": None, "ms": None})
                continue
            ip = parts[1] if len(parts) > 1 else None
            try:
                ms = float(parts[2]) if len(parts) > 2 else None
            except Exception:
                ms = None
            hop = {"hop": hop_no, "ip": ip, "ms": ms}
            if ip:
                geo = geo_lookup(ip)
                if geo:
                    hop.update(geo)
            hops.append(hop)
        return {"target": target, "hops": hops, "raw": result.stdout}
    except subprocess.TimeoutExpired:
        return {"target": target, "hops": [], "raw": "Traceroute timed out"}
    except Exception as exc:
        return {"target": target, "hops": [], "raw": str(exc)}


@app.after_request
def harden_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    return response


@app.route("/")
def index():
    return send_from_directory(STATIC_DIR, "index.html")


@app.route("/api/status")
def api_status():
    ensure_workers()
    return jsonify(
        {
            "server": SERVER_NAME,
            "interface": INTERFACE,
            "is_root": is_root(),
            "has_tcpdump": command_exists("tcpdump"),
            "tcpdump_running": bool(capture_process and capture_process.poll() is None),
            "packets_captured": len(snapshot_packets()),
            "uptime_sec": int(time.time() - status_started_at),
        }
    )


@app.route("/api/traffic_map")
def api_traffic_map():
    ensure_workers()
    return jsonify(build_traffic_map())


@app.route("/api/bandwidth")
def api_bandwidth():
    ensure_workers()
    with bandwidth_lock:
        return jsonify(list(bandwidth_samples))


@app.route("/api/packets")
def api_packets():
    ensure_workers()
    packets = snapshot_packets()
    if not packets:
        packets = [
            {
                "ts": now_clock(),
                "src": LOCAL_IP,
                "dst": conn["raddr"].split(":", 1)[0],
                "sp": 0,
                "dp": 0,
                "proto": "TCP",
                "len": 65536,
                "dir": "OUT",
                "src_co": "Local",
                "dst_co": "",
            }
            for conn in snapshot_connections()[:30]
        ]
    return jsonify(packets)


@app.route("/api/connections")
def api_connections():
    ensure_workers()
    return jsonify(snapshot_connections())


@app.route("/api/processes")
def api_processes():
    ensure_workers()
    return jsonify(process_rows())


@app.route("/api/sonde", methods=["POST"])
def api_sonde():
    ensure_workers()
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400

    result = {
        "target": target,
        "ts": now_iso(),
        "geo": probe_geo(target),
        "rdns": {"hostname": None},
        "ping": probe_ping(target),
        "ports": probe_ports(target),
        "ssl": probe_ssl(target),
        "dns": probe_dns(target),
        "whois": probe_whois(target),
        "bgp": probe_bgp(target),
    }
    try:
        resolved = resolve_host(target)
        if resolved:
            result["rdns"] = {"hostname": socket.gethostbyaddr(resolved)[0]}
    except Exception:
        pass
    return jsonify(result)


@app.route("/api/traceroute", methods=["POST"])
def api_traceroute():
    ensure_workers()
    payload = request.get_json(silent=True) or {}
    target = (payload.get("target") or "").strip()
    if not target:
        return jsonify({"error": "target required"}), 400
    return jsonify(traceroute_hops(target))


@app.route("/api/run_cmd", methods=["POST"])
def api_run_cmd():
    payload = request.get_json(silent=True) or {}
    command_text = (payload.get("cmd") or "").strip()
    if not command_text:
        return jsonify({"out": "", "err": "No command provided."})
    try:
        parts = shlex.split(command_text)
    except ValueError as exc:
        return jsonify({"out": "", "err": f"Could not parse command: {exc}"})
    ok, err = validate_run_command(parts)
    if not ok:
        return jsonify({"out": "", "err": err})
    try:
        timeout = TRACEROUTE_TIMEOUT if parts[0] == "traceroute" else SAFE_CMD_TIMEOUT
        return jsonify(run_command(parts, timeout=timeout))
    except subprocess.TimeoutExpired:
        return jsonify({"out": "", "err": "Command timed out."})
    except Exception as exc:
        return jsonify({"out": "", "err": str(exc)})


@app.route("/api/folder_info")
def api_folder_info():
    return jsonify(folder_rows())


@app.route("/api/open_folder", methods=["POST"])
def api_open_folder():
    payload = request.get_json(silent=True) or {}
    path = (payload.get("path") or "").strip()
    if not path:
        return jsonify({"ok": False, "err": "path required"}), 400

    full = safe_realpath(path)
    allowed = [
        safe_realpath(APP_DIR),
        safe_realpath(LOG_DIR),
        safe_realpath("~/Downloads"),
        safe_realpath("~/Documents"),
        safe_realpath("~/Desktop"),
    ]
    if not any(path_within(full, root) for root in allowed):
        return jsonify({"ok": False, "err": "Path not allowed"}), 403
    if not os.path.exists(full):
        return jsonify({"ok": False, "err": "Path does not exist"}), 404

    try:
        subprocess.Popen(["open", full])
        return jsonify({"ok": True})
    except Exception as exc:
        return jsonify({"ok": False, "err": str(exc)}), 500


@app.route("/api/device_adapters")
def api_device_adapters():
    return jsonify(list_device_adapters())


@app.route("/favicon.ico")
def favicon():
    return ("", 204)


def shutdown_capture():
    global capture_process
    proc = capture_process
    capture_process = None
    if not proc:
        return
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def bootstrap():
    ensure_log_dir()
    ensure_workers()


bootstrap()


if __name__ == "__main__":
    print(f"[NetWatch] Starting on http://{HOST}:{PORT}", flush=True)
    if PUBLIC_IP:
        print(f"[NetWatch] My IP: {LOCAL_IP}  Public: {PUBLIC_IP}", flush=True)
    else:
        print(f"[NetWatch] My IP: {LOCAL_IP}", flush=True)
    print(
        f"[NetWatch] Capture mode: {'tcpdump live feed' if is_root() and command_exists('tcpdump') else 'safe local mode'}",
        flush=True,
    )
    try:
        app.run(host=HOST, port=PORT, debug=False, threaded=True)
    finally:
        shutdown_capture()
