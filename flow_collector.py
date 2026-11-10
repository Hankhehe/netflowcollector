# flow_collector.py
import argparse
import json
import os
import queue
import socket
import struct
import sys
import threading
import time
import uuid
import ipaddress
from typing import Dict, Tuple, List, Any
import clickhouse_connect

# ---------------- ClickHouse Background Writer ----------------
class ClickHouseWriter:
    def __init__(self, q: queue.Queue):
        self.q = q
        self.client = None
        self.ch_host = os.getenv("CLICKHOUSE_HOST", "192.168.10.12")
        self.ch_port = int(os.getenv("CLICKHOUSE_PORT", "8123"))
        self.ch_user = os.getenv("CLICKHOUSE_USER", "admin")
        self.ch_password = os.getenv("CLICKHOUSE_PASSWORD", "111aaaBBB")
        self.buffer = []  # Local queue backup if ClickHouse goes down

    def init_client(self):
        print(f"[ClickHouseWriter] Connecting to ClickHouse at {self.ch_host}:{self.ch_port}...", file=sys.stderr)
        self.client = clickhouse_connect.get_client(
            host=self.ch_host,
            port=self.ch_port,
            username=self.ch_user,
            password=self.ch_password
        )
        
        # Determine retention days from settings
        retention_days = 7
        try:
            import sqlite3
            db_path = os.getenv("SQLITE_DB_PATH", "/data/flows.db")
            if not os.path.exists(db_path): db_path = "flows.db"
            if os.path.exists(db_path):
                conn = sqlite3.connect(db_path)
                cur = conn.cursor()
                cur.execute("SELECT value FROM system_settings WHERE key = 'retention_days'")
                row = cur.fetchone()
                if row and row[0]:
                    retention_days = max(1, int(row[0]))
                conn.close()
        except Exception:
            pass

        # Verify / Create tables with dynamic TTL
        self.client.command(f"""
        CREATE TABLE IF NOT EXISTS ipfix (
            id String,
            exporter String,
            proto String,
            src String,
            dst String,
            sport UInt16,
            dport UInt16,
            packets UInt64,
            octets UInt64,
            protocol Nullable(UInt16),
            json_data String,
            ts DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (ts, exporter, src, dst)
        TTL ts + INTERVAL {retention_days} DAY
        """)
        
        self.client.command(f"""
        CREATE TABLE IF NOT EXISTS netflow9 (
            id String,
            exporter String,
            proto String,
            src String,
            dst String,
            sport UInt16,
            dport UInt16,
            packets UInt64,
            octets UInt64,
            protocol Nullable(UInt16),
            json_data String,
            ts DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (ts, exporter, src, dst)
        TTL ts + INTERVAL {retention_days} DAY
        """)
        
        # Ensure TTL is applied to existing tables if they were created without it
        try:
            self.client.command(f"ALTER TABLE ipfix MODIFY TTL ts + INTERVAL {retention_days} DAY")
            self.client.command(f"ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL {retention_days} DAY")
        except Exception as alter_err:
            print(f"[ClickHouseWriter] Warning altering TTL: {alter_err}", file=sys.stderr)
            
        print(f"[ClickHouseWriter] ClickHouse tables initialized with {retention_days}-day TTL.", file=sys.stderr)

    def run(self):
        while True:
            # Connect or reconnect to ClickHouse if needed
            if self.client is None:
                try:
                    self.init_client()
                except Exception as e:
                    print(f"[ClickHouseWriter] ClickHouse connection error: {e}. Retrying in 5 seconds...", file=sys.stderr)
                    time.sleep(5)
                    continue

            # Drain memory queue
            items = []
            while not self.q.empty():
                try:
                    items.append(self.q.get_nowait())
                except queue.Empty:
                    break

            if not items and not self.buffer:
                time.sleep(1)
                continue

            # Merge any previously buffered failed items with new items
            all_items = self.buffer + items
            self.buffer = []

            # Separate items by table type
            ipfix_raw = []
            netflow9_raw = []
            for item in all_items:
                table, payload = item
                if table == "ipfix":
                    ipfix_raw.append(item)
                elif table == "netflow9":
                    netflow9_raw.append(item)

            # Insert IPFIX batch
            ipfix_success = True
            if ipfix_raw:
                try:
                    ipfix_data = []
                    for table, payload in ipfix_raw:
                        flow_id = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
                        sport = int(payload.get("sport") or 0)
                        dport = int(payload.get("dport") or 0)
                        if sport < 0 or sport > 65535: sport = 0
                        if dport < 0 or dport > 65535: dport = 0
                        
                        protocol_raw = payload.get("protocol")
                        protocol = int(protocol_raw) if protocol_raw is not None and str(protocol_raw).isdigit() else None
                        json_data = json.dumps(payload, separators=(",", ":"))
                        
                        ipfix_data.append([
                            flow_id, str(payload.get("exporter") or ""), str(payload.get("proto") or ""),
                            str(payload.get("src") or ""), str(payload.get("dst") or ""), sport, dport,
                            int(payload.get("packets") or 0), int(payload.get("octets") or 0), protocol, json_data
                        ])
                    
                    self.client.insert(
                        table="ipfix",
                        data=ipfix_data,
                        column_names=['id', 'exporter', 'proto', 'src', 'dst', 'sport', 'dport', 'packets', 'octets', 'protocol', 'json_data']
                    )
                    print(f"[ClickHouseWriter] Batch inserted {len(ipfix_data)} ipfix records", file=sys.stderr)
                except Exception as e:
                    print(f"[ClickHouseWriter] Failed to insert ipfix data: {e}", file=sys.stderr)
                    ipfix_success = False
                    self.buffer.extend(ipfix_raw)

            # Insert NetFlow v9 batch
            nf9_success = True
            if netflow9_raw:
                try:
                    nf9_data = []
                    for table, payload in netflow9_raw:
                        flow_id = f"{int(time.time() * 1000)}-{uuid.uuid4().hex[:8]}"
                        sport = int(payload.get("sport") or 0)
                        dport = int(payload.get("dport") or 0)
                        if sport < 0 or sport > 65535: sport = 0
                        if dport < 0 or dport > 65535: dport = 0
                        
                        protocol_raw = payload.get("protocol")
                        protocol = int(protocol_raw) if protocol_raw is not None and str(protocol_raw).isdigit() else None
                        json_data = json.dumps(payload, separators=(",", ":"))
                        
                        nf9_data.append([
                            flow_id, str(payload.get("exporter") or ""), str(payload.get("proto") or ""),
                            str(payload.get("src") or ""), str(payload.get("dst") or ""), sport, dport,
                            int(payload.get("packets") or 0), int(payload.get("octets") or 0), protocol, json_data
                        ])
                    
                    self.client.insert(
                        table="netflow9",
                        data=nf9_data,
                        column_names=['id', 'exporter', 'proto', 'src', 'dst', 'sport', 'dport', 'packets', 'octets', 'protocol', 'json_data']
                    )
                    print(f"[ClickHouseWriter] Batch inserted {len(nf9_data)} netflow9 records", file=sys.stderr)
                except Exception as e:
                    print(f"[ClickHouseWriter] Failed to insert netflow9 data: {e}", file=sys.stderr)
                    nf9_success = False
                    self.buffer.extend(netflow9_raw)

            # If either database insertion fails, close ClickHouse client to force reconnection
            if not ipfix_success or not nf9_success:
                self.client = None
                print("[ClickHouseWriter] Resetting client connection due to failure. Retrying in 5 seconds...", file=sys.stderr)
                time.sleep(5)
            else:
                time.sleep(1)

# ---------------- Common helpers ----------------
def ip4(b: bytes) -> str:
    return ".".join(str(x) for x in b)

def try_ip(v: bytes, l: int) -> str:
    if l == 4 and len(v) == 4: return ip4(v)
    return v.hex()

# ---------------- NetFlow v9 ----------------
NFV9_FIELDS = {
    1: ("octets", 4),            # IN_BYTES
    2: ("packets", 4),           # IN_PKTS
    4: ("protocol", 1),
    5: ("tos", 1),
    6: ("tcp_flags", 1),
    7: ("sport", 2),
    8: ("src", 4),
    11: ("dport", 2),
    12: ("dst", 4),
    21: ("last_switched", 4),
    22: ("first_switched", 4),
    61: ("direction", 1),
}

def get_db_collector_ports(default_nf=2055, default_ipfix=4739):
    db_path = os.getenv("SQLITE_DB_PATH", "/data/flows.db")
    if not os.path.exists(db_path):
        db_path = "flows.db"
    if not os.path.exists(db_path):
        return default_nf, default_ipfix
    
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("SELECT key, value FROM system_settings WHERE key IN ('netflow_port', 'ipfix_port')")
        rows = dict(cur.fetchall())
        conn.close()
        nf_port = int(rows.get("netflow_port", default_nf))
        ipfix_port = int(rows.get("ipfix_port", default_ipfix))
        return nf_port, ipfix_port
    except Exception:
        return default_nf, default_ipfix

def get_db_allowed_cidrs():
    db_path = os.getenv("SQLITE_DB_PATH", "/data/flows.db")
    if not os.path.exists(db_path):
        db_path = "flows.db"
    if not os.path.exists(db_path):
        return []
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS collector_allowed_cidrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at DATETIME
        )""")
        cur.execute("SELECT cidr FROM collector_allowed_cidrs")
        rows = [r[0].strip() for r in cur.fetchall() if r[0] and r[0].strip()]
        conn.close()
        networks = []
        for r in rows:
            try:
                networks.append(ipaddress.ip_network(r, strict=False))
            except Exception:
                pass
        return networks
    except Exception:
        return []

class NetFlowV9Collector:
    def __init__(self, host: str, port: int, q: queue.Queue):
        self.host = host
        self.port = port
        self.q = q
        self.sock = None
        self.templates: Dict[Tuple[str,int], Dict[int, List[Tuple[int,int]]]] = {}
        self.allowed_cidrs = get_db_allowed_cidrs()
        self.bind_socket()

    def bind_socket(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(2.0)
            s.bind((self.host, self.port))
            self.sock = s
            print(f"[NetFlowV9Collector] Successfully listening on UDP {self.host}:{self.port}", file=sys.stderr)
        except Exception as e:
            print(f"[NetFlowV9Collector] Error binding UDP {self.host}:{self.port}: {e}", file=sys.stderr)

    def update_port(self, new_port: int):
        if self.port != new_port:
            print(f"[NetFlowV9Collector] Updating listening port: {self.port} -> {new_port}", file=sys.stderr)
            self.port = new_port
            self.bind_socket()

    def update_allowed_cidrs(self, new_cidrs):
        self.allowed_cidrs = new_cidrs

    def run(self):
        while True:
            if not self.sock:
                self.bind_socket()
                if not self.sock:
                    time.sleep(2)
                    continue
            try:
                data, (ip, _port) = self.sock.recvfrom(65535)
                if self.allowed_cidrs:
                    try:
                        addr = ipaddress.ip_address(ip)
                        if not any(addr in net for net in self.allowed_cidrs):
                            continue
                    except Exception:
                        continue
                self.handle_packet(ip, data)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[NetFlowV9Collector] Socket error: {e}", file=sys.stderr)
                time.sleep(1)

    def handle_packet(self, exporter_ip: str, buf: bytes):
        if len(buf) < 20: return
        version, count, sys_uptime, unix_secs, seq, source_id = struct.unpack("!HHLLLL", buf[:20])
        if version != 9: return
        key = (exporter_ip, source_id)
        pos = 20
        while pos + 4 <= len(buf):
            flowset_id, length = struct.unpack("!HH", buf[pos:pos+4])
            if length < 4 or pos + length > len(buf): break
            body = buf[pos+4:pos+length]
            pos += length

            if flowset_id == 0:  # Template Set
                p = 0
                while p + 4 <= len(body):
                    template_id, field_count = struct.unpack("!HH", body[p:p+4])
                    p += 4
                    fields = []
                    for _ in range(field_count):
                        if p + 4 > len(body): break
                        f_type, f_len = struct.unpack("!HH", body[p:p+4])
                        p += 4
                        fields.append((f_type, f_len))
                    self.templates.setdefault(key, {})[template_id] = fields
            elif flowset_id == 1:
                # Options Template
                continue
            else:
                # Data FlowSet
                tmap = self.templates.get(key, {}).get(flowset_id)
                if not tmap:
                    continue
                p = 0
                rec_len = sum(fl for _, fl in tmap)
                while p + rec_len <= len(body):
                    rec = body[p:p+rec_len]
                    p += rec_len
                    out: Dict[str, Any] = {
                        "exporter": exporter_ip,
                        "proto": "netflow9",
                        "odid": source_id,
                        "seq": seq,
                        "first_switched": None,
                        "last_switched": None,
                    }
                    cursor = 0
                    for f_type, f_len in tmap:
                        val = rec[cursor:cursor+f_len]
                        cursor += f_len
                        name, _ = NFV9_FIELDS.get(f_type, (f"f{f_type}", None))
                        if name in ("src","dst"):
                            out[name] = try_ip(val, f_len)
                        elif f_len in (1,2,4,8):
                            out[name] = int.from_bytes(val, "big")
                        else:
                            out[name] = val.hex()
                    normalized = self._normalize(out)
                    self.q.put(("netflow9", normalized))

    def _normalize(self, d: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "exporter": d.get("exporter",""),
            "proto": d.get("proto","netflow9"),
            "odid": d.get("odid",""),
            "seq": d.get("seq",""),
            "src": d.get("src",""),
            "dst": d.get("dst",""),
            "sport": d.get("sport",""),
            "dport": d.get("dport",""),
            "protocol": d.get("protocol",""),
            "packets": d.get("packets",""),
            "octets": d.get("octets",""),
            "first_switched": d.get("first_switched",""),
            "last_switched": d.get("last_switched",""),
        }

# ---------------- IPFIX (v10) ----------------
IPFIX_IE = {
    1: ("octets", 8),                     # octetDeltaCount
    2: ("packets", 8),                    # packetDeltaCount
    4: ("protocol", 1),                    # protocolIdentifier
    7: ("sport", 2),                       # sourceTransportPort
    8: ("src", 4),                         # sourceIPv4Address
    11: ("dport", 2),                      # destinationTransportPort
    12: ("dst", 4),                        # destinationIPv4Address
    27: ("src", 16),                       # sourceIPv6Address
    28: ("dst", 16),                       # destinationIPv6Address
    85: ("octets", 8),                     # octetTotalCount
    86: ("packets", 8),                    # packetTotalCount
    152: ("flowStartMilliseconds", 8),
    153: ("flowEndMilliseconds", 8),
}

class IPFIXCollector:
    def __init__(self, host: str, port: int, q: queue.Queue):
        self.host = host
        self.port = port
        self.q = q
        self.sock = None
        self.templates: Dict[Tuple[str,int], Dict[int, List[Tuple[int,int,int]]]] = {}
        self.allowed_cidrs = get_db_allowed_cidrs()
        self.bind_socket()

    def bind_socket(self):
        if self.sock:
            try: self.sock.close()
            except: pass
            self.sock = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.settimeout(2.0)
            s.bind((self.host, self.port))
            self.sock = s
            print(f"[IPFIXCollector] Successfully listening on UDP {self.host}:{self.port}", file=sys.stderr)
        except Exception as e:
            print(f"[IPFIXCollector] Error binding UDP {self.host}:{self.port}: {e}", file=sys.stderr)

    def update_port(self, new_port: int):
        if self.port != new_port:
            print(f"[IPFIXCollector] Updating listening port: {self.port} -> {new_port}", file=sys.stderr)
            self.port = new_port
            self.bind_socket()

    def update_allowed_cidrs(self, new_cidrs):
        self.allowed_cidrs = new_cidrs

    def run(self):
        while True:
            if not self.sock:
                self.bind_socket()
                if not self.sock:
                    time.sleep(2)
                    continue
            try:
                data, (ip, _port) = self.sock.recvfrom(65535)
                if self.allowed_cidrs:
                    try:
                        addr = ipaddress.ip_address(ip)
                        if not any(addr in net for net in self.allowed_cidrs):
                            continue
                    except Exception:
                        continue
                self.handle_packet(ip, data)
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[IPFIXCollector] Socket error: {e}", file=sys.stderr)
                time.sleep(1)

    def handle_packet(self, exporter_ip: str, buf: bytes):
        if len(buf) < 16: return
        version, length, export_time, seq, odid = struct.unpack("!HHLLL", buf[:16])
        if version != 10: return
        end = length if length <= len(buf) else len(buf)
        pos = 16
        key = (exporter_ip, odid)
        while pos + 4 <= end:
            set_id, set_len = struct.unpack("!HH", buf[pos:pos+4])
            if set_len < 4 or pos + set_len > end: break
            body = buf[pos+4:pos+set_len]
            pos += set_len

            if set_id == 2:  # Template Set
                p = 0
                while p + 4 <= len(body):
                    template_id, field_count = struct.unpack("!HH", body[p:p+4])
                    p += 4
                    fields = []
                    for _ in range(field_count):
                        if p + 4 > len(body): break
                        ie, flen = struct.unpack("!HH", body[p:p+4])
                        p += 4
                        ent = 0
                        if ie & 0x8000:
                            ie &= 0x7FFF
                            if p + 4 > len(body): break
                            ent = struct.unpack("!I", body[p:p+4])[0]
                            p += 4
                        fields.append((ie, flen, ent))
                    self.templates.setdefault(key, {})[template_id] = fields
            elif set_id == 3:
                # Options Template
                continue
            elif set_id >= 256:
                tmap = self.templates.get(key, {}).get(set_id)
                if not tmap:
                    continue
                rec_len = sum(flen for _, flen, _ in tmap)
                p = 0
                while rec_len and p + rec_len <= len(body):
                    rec = body[p:p+rec_len]
                    p += rec_len
                    out: Dict[str, Any] = {
                        "exporter": exporter_ip,
                        "proto": "ipfix",
                        "odid": odid,
                        "exportTime": export_time,
                        "seq": seq,
                    }
                    cursor = 0
                    for ie, flen, ent in tmap:
                        val = rec[cursor:cursor+flen]
                        cursor += flen
                        name, _ = IPFIX_IE.get(ie, (f"ie{ie}_e{ent}", None))
                        if name in ("src","dst"):
                            out[name] = try_ip(val, flen)
                        elif flen in (1,2,4,8):
                            out[name] = int.from_bytes(val, "big")
                        else:
                            out[name] = val.hex()
                    
                    norm = {
                        "exporter": out["exporter"],
                        "proto": "ipfix",
                        "odid": out["odid"],
                        "seq": out.get("seq",""),
                        "src": out.get("src",""),
                        "dst": out.get("dst",""),
                        "sport": out.get("sport",""),
                        "dport": out.get("dport",""),
                        "protocol": out.get("protocol",""),
                        "packets": out.get("packets",""),
                        "octets": out.get("octets",""),
                        "first_switched": out.get("flowStartMilliseconds",""),
                        "last_switched": out.get("flowEndMilliseconds",""),
                    }
                    self.q.put(("ipfix", norm))

def monitor_ports(nf_collector, ipfix_collector):
    last_cidrs_str = None
    while True:
        try:
            time.sleep(3)
            db_nf, db_ipfix = get_db_collector_ports(nf_collector.port, ipfix_collector.port)
            if db_nf != nf_collector.port:
                nf_collector.update_port(db_nf)
            if db_ipfix != ipfix_collector.port:
                ipfix_collector.update_port(db_ipfix)
            
            db_cidrs = get_db_allowed_cidrs()
            curr_str = ",".join(sorted(str(c) for c in db_cidrs))
            if curr_str != last_cidrs_str:
                last_cidrs_str = curr_str
                nf_collector.update_allowed_cidrs(db_cidrs)
                ipfix_collector.update_allowed_cidrs(db_cidrs)
                print(f"[Collector] Updated allowed CIDRs whitelist: {len(db_cidrs)} rule(s) active", file=sys.stderr)
        except Exception:
            time.sleep(3)

# ---------------- Runner ----------------
def main():
    ap = argparse.ArgumentParser(description="NetFlow v9 + IPFIX -> ClickHouse")
    ap.add_argument("--bind", default="0.0.0.0")
    ap.add_argument("--nf-port", type=int, default=None)
    ap.add_argument("--ipfix-port", type=int, default=None)
    args = ap.parse_args()

    db_nf, db_ipfix = get_db_collector_ports(2055, 4739)
    env_nf = int(os.getenv("NETFLOW_PORT", db_nf))
    env_ipfix = int(os.getenv("IPFIX_PORT", db_ipfix))

    nf_port = args.nf_port if args.nf_port is not None else env_nf
    ipfix_port = args.ipfix_port if args.ipfix_port is not None else env_ipfix

    q = queue.Queue()

    nf = NetFlowV9Collector(args.bind, nf_port, q)
    ipf = IPFIXCollector(args.bind, ipfix_port, q)
    writer = ClickHouseWriter(q)

    t1 = threading.Thread(target=nf.run, daemon=True)
    t2 = threading.Thread(target=ipf.run, daemon=True)
    t3 = threading.Thread(target=writer.run, daemon=True)
    t4 = threading.Thread(target=monitor_ports, args=(nf, ipf), daemon=True)
    
    t1.start()
    t2.start()
    t3.start()
    t4.start()

    print(f"NetFlow v9 listening on {args.bind}:{nf.port}", file=sys.stderr)
    print(f"IPFIX listening on {args.bind}:{ipf.port}", file=sys.stderr)
    try:
        while True:
            time.sleep(1)
            if not t1.is_alive():
                print("Fatal error: NetFlow v9 collector thread died!", file=sys.stderr)
                sys.exit(1)
            if not t2.is_alive():
                print("Fatal error: IPFIX collector thread died!", file=sys.stderr)
                sys.exit(1)
            if not t3.is_alive():
                print("Fatal error: ClickHouse writer thread died!", file=sys.stderr)
                sys.exit(1)
    except KeyboardInterrupt:
        print("stop")

if __name__ == "__main__":
    main()
