import os
import sqlite3
import json
import socket
import threading
import clickhouse_connect
import ipaddress
import time
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict, Any, Iterable
from fastapi import FastAPI, Query, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="Netflow Collector Web UI")

DB_PATH = os.getenv("SQLITE_DB_PATH", "flows.db")

ch_thread_local = threading.local()

def get_ch_client():
    if not hasattr(ch_thread_local, "client") or ch_thread_local.client is None:
        _ch_host = os.getenv("CLICKHOUSE_HOST", "192.168.10.12")
        _ch_port = int(os.getenv("CLICKHOUSE_PORT", "8123"))
        _ch_user = os.getenv("CLICKHOUSE_USER", "admin")
        _ch_password = os.getenv("CLICKHOUSE_PASSWORD", "111aaaBBB")
        ch_thread_local.client = clickhouse_connect.get_client(
            host=_ch_host,
            port=_ch_port,
            username=_ch_user,
            password=_ch_password
        )
    return ch_thread_local.client

def reset_ch_client():
    if hasattr(ch_thread_local, "client"):
        try:
            ch_thread_local.client.close()
        except Exception:
            pass
        ch_thread_local.client = None

# Background DNS Resolver setup
dns_executor = ThreadPoolExecutor(max_workers=5)
resolving_ips = set()
resolving_lock = threading.Lock()

def _resolve_and_save(ip: str):
    try:
        # socket.gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
        hostname, _, _ = socket.gethostbyaddr(ip)
    except Exception:
        hostname = ""
    
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cur = conn.cursor()
        cur.execute(
            "INSERT OR REPLACE INTO dns_cache (ip, domain, last_resolved) VALUES (?, ?, CURRENT_TIMESTAMP)",
            (ip, hostname)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DNS Resolver] Error writing {ip} -> {hostname} to db: {e}")
    finally:
        with resolving_lock:
            resolving_ips.discard(ip)

def enqueue_dns_resolution(ip: str):
    if not ip or ip == "0.0.0.0" or ip == "-":
        return
    with resolving_lock:
        if ip in resolving_ips:
            return
        resolving_ips.add(ip)
    dns_executor.submit(_resolve_and_save, ip)

def get_dns_mappings(ips: set) -> Dict[str, str]:
    if not ips:
        return {}
    
    dns_map = {}
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        placeholders = ",".join("?" for _ in ips)
        cur.execute(f"SELECT ip, domain, last_resolved FROM dns_cache WHERE ip IN ({placeholders})", list(ips))
        rows = cur.fetchall()
        conn.close()
        
        cached_ips = set()
        for row in rows:
            ip = row["ip"]
            domain = row["domain"]
            last_resolved_str = row["last_resolved"]
            cached_ips.add(ip)
            
            # Check if fresh (24h)
            fresh = True
            if last_resolved_str:
                try:
                    last_resolved = datetime.strptime(last_resolved_str, "%Y-%m-%d %H:%M:%S")
                    if now - last_resolved > timedelta(days=1):
                        fresh = False
                except Exception:
                    pass
            
            dns_map[ip] = domain
            if not fresh:
                enqueue_dns_resolution(ip)
                
        # For any queried IP that was not in the cache, queue it for resolution
        for ip in ips:
            if ip not in cached_ips:
                enqueue_dns_resolution(ip)
                dns_map[ip] = ""
    except Exception as e:
        print(f"[DNS Cache] Error reading cache: {e}")
        # Queue anyway on error
        for ip in ips:
            enqueue_dns_resolution(ip)
            dns_map[ip] = ""
            
    return dns_map


# Protocol mapping
PROTO_MAP = {
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "ipv6": 41,
    "ospf": 89,
    "sctp": 132,
}

PROTO_NAME_MAP = {v: k.upper() for k, v in PROTO_MAP.items()}

def get_proto_number(proto_str: str) -> Optional[int]:
    if not proto_str:
        return None
    proto_str = proto_str.lower().strip()
    if proto_str.isdigit():
        return int(proto_str)
    return PROTO_MAP.get(proto_str)

def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        name = col[0]
        val = row[idx]
        d[name] = val
    # Add friendly protocol name if present
    if "protocol" in d and d["protocol"] is not None:
        d["proto_name"] = PROTO_NAME_MAP.get(d["protocol"], f"UNKNOWN ({d['protocol']})")
    else:
        d["proto_name"] = "N/A"
    return d

def get_db_connection():
    # Use standard connection with a timeout to avoid URI-parsing bugs on different OS's
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = dict_factory
    
    # SQLite optimization PRAGMAs for high performance reads and concurrent write support
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA cache_size = -64000")  # 64MB Cache
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA synchronous = NORMAL")
    
    return conn

port_aliases_cache = {}
ip_aliases_cache = {}

def ip_to_hex(ip_obj) -> str:
    if ip_obj.version == 4:
        return 'v4-' + ip_obj.packed.hex()
    return 'v6-' + ip_obj.packed.hex()

def load_port_aliases():
    global port_aliases_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT port, name FROM port_aliases")
        port_aliases_cache = {row[0]: row[1] for row in cur.fetchall()}
        conn.close()
        print(f"[Startup Init] Loaded {len(port_aliases_cache)} port aliases into cache.")
    except Exception as e:
        print(f"[Startup Init] Error loading port aliases into cache: {e}")

def load_ip_aliases():
    global ip_aliases_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Only load exact IP matches into memory cache to save memory
        cur.execute("SELECT ip, name FROM ip_aliases WHERE ip NOT LIKE '%/%'")
        rows = cur.fetchall()
        conn.close()
        
        ip_aliases_cache = {row[0].strip(): row[1].strip() for row in rows}
        print(f"[Startup Init] Loaded {len(ip_aliases_cache)} exact IP aliases into cache.")
    except Exception as e:
        print(f"[Startup Init] Error loading IP aliases into cache: {e}")

def resolve_ip_alias(ip_str: str) -> Optional[str]:
    if not ip_str:
        return None
    ip_str = ip_str.strip()
    ip_lower = ip_str.lower()
    if ip_lower == "internal":
        return "Private IP"
    elif ip_lower == "external":
        return "Public IP"
    
    # 1. Exact match first
    if ip_str in ip_aliases_cache:
        return ip_aliases_cache[ip_str]

def build_ip_where_clause(col: str, ip_query: str, params: dict, param_key: str) -> str:
    val = ip_query.strip().lower()
    if val == "internal":
        return f"(isIPv4String({col}) OR isIPv6String({col})) AND (isIPAddressInRange({col}, '192.168.0.0/16') OR isIPAddressInRange({col}, '172.16.0.0/12') OR isIPAddressInRange({col}, '10.0.0.0/8'))"
    elif val == "external":
        return f"(isIPv4String({col}) OR isIPv6String({col})) AND NOT (isIPAddressInRange({col}, '192.168.0.0/16') OR isIPAddressInRange({col}, '172.16.0.0/12') OR isIPAddressInRange({col}, '10.0.0.0/8'))"
    else:
        params[param_key] = f"{ip_query}%"
        return f"{col} LIKE %({param_key})s"
        
    # 2. CIDR range match from SQLite
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        ip_hex = ip_to_hex(ip_obj)
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT name FROM ip_aliases 
            WHERE start_ip <= ? AND end_ip >= ? 
            ORDER BY prefix_len DESC LIMIT 1
        """, (ip_hex, ip_hex))
        row = cur.fetchone()
        conn.close()
        
        alias = row[0] if row else None
        if alias:
            # Cache resolved IP for future O(1) lookups
            ip_aliases_cache[ip_str] = alias
        return alias
    except Exception:
        pass
        
    return None

def resolve_ip_aliases_batch(ips_list: Iterable[str]) -> Dict[str, str]:
    results = {}
    missing_ips = []
    
    for ip in ips_list:
        if not ip:
            continue
        ip_clean = ip.strip()
        if ip_clean in ip_aliases_cache:
            results[ip_clean] = ip_aliases_cache[ip_clean]
        else:
            missing_ips.append(ip_clean)
            
    if not missing_ips:
        return results
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        for ip in missing_ips:
            try:
                ip_obj = ipaddress.ip_address(ip)
                ip_hex = ip_to_hex(ip_obj)
                
                cur.execute("""
                    SELECT name FROM ip_aliases 
                    WHERE start_ip <= ? AND end_ip >= ? 
                    ORDER BY prefix_len DESC LIMIT 1
                """, (ip_hex, ip_hex))
                row = cur.fetchone()
                if row:
                    alias = row[0]
                    results[ip] = alias
                    ip_aliases_cache[ip] = alias  # Cache it
            except Exception:
                pass
                
        conn.close()
    except Exception as e:
        print(f"Error in batch resolve: {e}")
        
    return results

def init_db():
    """Verify that tables exist, run auto-migration for missing columns, and create indexes on startup."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        cur.execute("""CREATE TABLE IF NOT EXISTS dns_cache (
            ip TEXT PRIMARY KEY,
            domain TEXT,
            last_resolved DATETIME DEFAULT CURRENT_TIMESTAMP
        )""")
        
        cur.execute("CREATE INDEX IF NOT EXISTS idx_dns_cache_ip ON dns_cache (ip)")
        
        # Initialize port aliases table
        cur.execute("""CREATE TABLE IF NOT EXISTS port_aliases (
            port INTEGER PRIMARY KEY,
            name TEXT NOT NULL
        )""")
        
        # Check if table is empty to pre-populate defaults
        cur.execute("SELECT COUNT(*) FROM port_aliases")
        if cur.fetchone()[0] == 0:
            defaults = [
                (20, "FTP-Data"),
                (21, "FTP"),
                (22, "SSH"),
                (23, "Telnet"),
                (25, "SMTP"),
                (53, "DNS"),
                (67, "DHCP-Server"),
                (68, "DHCP-Client"),
                (80, "HTTP"),
                (110, "POP3"),
                (123, "NTP"),
                (143, "IMAP"),
                (161, "SNMP"),
                (443, "HTTPS"),
                (445, "Microsoft-DS"),
                (993, "IMAPS"),
                (995, "POP3S"),
                (1433, "MSSQL"),
                (2055, "Netflow"),
                (3306, "MySQL"),
                (3389, "RDP"),
                (4739, "IPFIX"),
                (5432, "PostgreSQL"),
                (8080, "HTTP-ALT")
            ]
            cur.executemany("INSERT INTO port_aliases (port, name) VALUES (?, ?)", defaults)
            conn.commit()
            print("[Startup Init] SQLite default port aliases pre-populated.")
            
        # Initialize ip aliases table
        cur.execute("""CREATE TABLE IF NOT EXISTS ip_aliases (
            ip TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            start_ip TEXT,
            end_ip TEXT,
            prefix_len INTEGER
        )""")
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_aliases_range ON ip_aliases (start_ip, end_ip, prefix_len)")
        
        # Initialize audit rules table
        cur.execute("""CREATE TABLE IF NOT EXISTS audit_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port TEXT,
            flag TEXT CHECK(flag IN ('watch', 'anomaly')),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(ip, port)
        )""")
        
        # Initialize audit logs table
        cur.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_ts DATETIME DEFAULT CURRENT_TIMESTAMP,
            status TEXT,
            records_matched INTEGER DEFAULT 0,
            message TEXT
        )""")
        
        conn.commit()
        conn.close()
        print("[Startup Init] SQLite DNS cache, port, IP aliases, and audit tables initialized successfully.")
        
        load_port_aliases()
        load_ip_aliases()
    except Exception as e:
        print(f"[Startup Init] Error initializing SQLite tables: {e}")

    # Initialize ClickHouse tables if they do not exist
    try:
        client = get_ch_client()
        client.command("""
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
        TTL ts + INTERVAL 7 DAY
        """)
        
        client.command("""
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
        TTL ts + INTERVAL 7 DAY
        """)
        
        # Initialize matched_flows table (without TTL)
        client.command("""
        CREATE TABLE IF NOT EXISTS matched_flows (
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
            ts DateTime,
            rule_ip Nullable(String),
            rule_port Nullable(String),
            match_flag String,
            match_ts DateTime DEFAULT now()
        ) ENGINE = MergeTree()
        ORDER BY (match_ts, ts, exporter, src, dst)
        """)
        
        # Ensure TTL is applied to existing tables if they were created without it
        try:
            client.command("ALTER TABLE ipfix MODIFY TTL ts + INTERVAL 7 DAY")
            client.command("ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL 7 DAY")
        except Exception as alter_err:
            print(f"[Startup Init] Warning altering ClickHouse TTL: {alter_err}")
            
        print("[Startup Init] ClickHouse database tables initialized successfully.")
    except Exception as e:
        print(f"[Startup Init] Error initializing ClickHouse tables: {e}")

@app.on_event("startup")
def on_startup():
    init_db()
    # Start background daily traffic audit scheduler
    t = threading.Thread(target=audit_scheduler_loop, daemon=True)
    t.start()

@app.get("/api/exporters")
def get_exporters():
    """Get a list of all distinct exporter IPs from both tables."""
    try:
        client = get_ch_client()
        result = client.query("""
            SELECT DISTINCT exporter FROM (
                SELECT exporter FROM ipfix
                UNION ALL
                SELECT exporter FROM netflow9
            ) WHERE exporter IS NOT NULL AND exporter != ''
        """)
        exporters = [row[0] for row in result.result_rows]
        return exporters
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/flows")
def get_flows(
    table: str = Query("all", description="Table to search: 'all', 'ipfix', 'netflow9'"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    time_range: str = Query("all", description="Time range: '10m', '1h', '24h', '7d', 'all'"),
    start_time: Optional[str] = Query(None, description="Start UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    end_time: Optional[str] = Query(None, description="End UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    sort_by: str = Query("ts", description="Sort field: 'type', 'ts', 'exporter', 'src', 'sport', 'dst', 'dport', 'proto', 'packets', 'octets'"),
    sort_order: str = Query("desc", description="Sort order: 'asc', 'desc'"),
    group_by: Optional[str] = Query(None, description="Columns to group by, comma-separated")
):
    """Query flow records with filtering, sorting, optional dynamic grouping, and pagination."""
    try:
        client = get_ch_client()

        where_clauses = []
        params = {}

        if src:
            where_clauses.append(build_ip_where_clause("src", src, params, "src"))
        if dst:
            where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
        if sport is not None:
            where_clauses.append("sport = %(sport)s")
            params["sport"] = sport
        if dport is not None:
            where_clauses.append("dport = %(dport)s")
            params["dport"] = dport
        if exporter:
            exp_parts = [e.strip() for e in exporter.split(",") if e.strip()]
            if exp_parts:
                where_clauses.append("exporter IN %(exporter_list)s")
                params["exporter_list"] = tuple(exp_parts)
        
        # Support multi-select protocols (comma-separated TCP,UDP)
        if proto:
            proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
            if proto_parts:
                proto_nums = []
                has_na = False
                for p in proto_parts:
                    if p.upper() == "N/A":
                        has_na = True
                        continue
                    p_num = get_proto_number(p)
                    if p_num is not None:
                        proto_nums.append(p_num)
                
                sub_clauses = []
                if proto_nums:
                    sub_clauses.append("protocol IN %(proto_nums)s")
                    params["proto_nums"] = tuple(proto_nums)
                if has_na:
                    sub_clauses.append("protocol IS NULL")
                
                if sub_clauses:
                    where_clauses.append("(" + " OR ".join(sub_clauses) + ")")

        # Handle time range (ClickHouse timestamps)
        if start_time or end_time:
            if start_time:
                where_clauses.append("ts >= %(start_time)s")
                params["start_time"] = start_time
            if end_time:
                where_clauses.append("ts <= %(end_time)s")
                params["end_time"] = end_time
        else:
            if time_range == "10m":
                where_clauses.append("ts >= now() - INTERVAL 10 MINUTE")
            elif time_range == "1h":
                where_clauses.append("ts >= now() - INTERVAL 1 HOUR")
            elif time_range == "24h":
                where_clauses.append("ts >= now() - INTERVAL 24 HOUR")
            elif time_range == "7d":
                where_clauses.append("ts >= now() - INTERVAL 7 DAY")

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        # Decide source table/UNION query
        tables = [t.strip().lower() for t in table.split(",") if t.strip()] if table else []
        has_ipfix = "ipfix" in tables or not tables or "all" in tables
        has_nf9 = "netflow9" in tables or not tables or "all" in tables

        if has_ipfix and not has_nf9:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix"
        elif has_nf9 and not has_ipfix:
            source_select = "SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9"
        elif has_ipfix and has_nf9:
            source_select = """
                SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix
                UNION ALL
                SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9
            """
        else:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix WHERE 1=0"

        # Map sorting field to database column safely to prevent SQL injection
        sort_by_map = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol",
            "packets": "packets",
            "octets": "octets"
        }
        db_sort_by = sort_by_map.get(sort_by.lower(), "ts")
        db_sort_order = "DESC" if sort_order.lower() == "desc" else "ASC"

        # Check for dynamic aggregation / group by
        allowed_group_cols = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol"
        }

        cols_to_group = []
        if group_by:
            cols_to_group = [allowed_group_cols[c] for c in group_by.split(",") if c in allowed_group_cols]

        if cols_to_group:
            # Adjust sorting fields for aggregated queries to resolve ambiguity in ClickHouse
            if db_sort_by == "packets":
                db_sort_by = "sum_packets"
            elif db_sort_by == "octets":
                db_sort_by = "sum_bytes"
            elif db_sort_by == "ts" and "ts" not in cols_to_group:
                db_sort_by = "max_ts"

            # Aggregate selected fields and pad rest with NULL
            select_list = []
            for col in cols_to_group:
                select_list.append(col)
            
            select_list.append("SUM(packets) as sum_packets")
            select_list.append("SUM(octets) as sum_bytes")
            
            if "ts" not in cols_to_group:
                select_list.append("MAX(ts) as max_ts")
            
            # Pad all unselected/ungrouped fields with NULL
            all_fields = {
                "type": "type",
                "exporter": "exporter",
                "src": "src",
                "sport": "sport",
                "dst": "dst",
                "dport": "dport",
                "protocol": "protocol"
            }
            for key, col in all_fields.items():
                if col not in cols_to_group:
                    select_list.append(f"CAST(NULL, 'Nullable(String)') as {col}" if col in ("type", "exporter", "src", "dst") else f"CAST(NULL, 'Nullable(UInt16)') as {col}")
            
            select_str = ", ".join(select_list)
            group_str = "GROUP BY " + ", ".join(cols_to_group)
            
            sql = f"""
                SELECT {select_str} FROM ({source_select})
                {where_str}
                {group_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT %(limit)s OFFSET %(offset)s
            """
            
            count_sql = f"""
                SELECT COUNT() as total FROM (
                    SELECT 1 FROM ({source_select})
                    {where_str}
                    {group_str}
                )
            """
        else:
            # Default unaggregated query
            sql = f"""
                SELECT * FROM ({source_select})
                {where_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT %(limit)s OFFSET %(offset)s
            """
            count_sql = f"""
                SELECT COUNT() as total FROM ({source_select})
                {where_str}
            """

        # Execute count query
        count_res = client.query(count_sql, parameters=params)
        total_count = count_res.result_rows[0][0]

        # Execute data query
        params["limit"] = limit
        params["offset"] = offset
        result = client.query(sql, parameters=params)
        
        records = []
        for r_row in result.result_rows:
            r = dict(zip(result.column_names, r_row))
            # Rename aggregated aliases back to expected keys for frontend compatibility
            if "sum_packets" in r:
                r["packets"] = r["sum_packets"]
            if "sum_bytes" in r:
                r["octets"] = r["sum_bytes"]
            if "max_ts" in r:
                r["ts"] = r["max_ts"]
            # Parse json_data fields for raw detail rendering if requested
            if r.get("json_data"):
                try:
                    r["raw_details"] = json.loads(r["json_data"])
                except Exception:
                    r["raw_details"] = {}
            else:
                r["raw_details"] = {}
                
            # Attaching proto_name
            if "protocol" in r and r["protocol"] is not None:
                r["proto_name"] = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})")
            else:
                r["proto_name"] = "N/A"
                
            # Attaching port names from cache
            r["sport_name"] = port_aliases_cache.get(r.get("sport"), "")
            r["dport_name"] = port_aliases_cache.get(r.get("dport"), "")
            
            records.append(r)

        # Collect unique IPs to resolve
        ips_to_resolve = set()
        for r in records:
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
        
        # Get DNS and IP Aliases mappings in batch
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)
        
        # Attach domains to records (IP alias takes priority over DNS cache resolved domain)
        for r in records:
            src_ip = r.get("src")
            dst_ip = r.get("dst")
            r["src_domain"] = alias_map.get(src_ip) or dns_map.get(src_ip, "")
            r["dst_domain"] = alias_map.get(dst_ip) or dns_map.get(dst_ip, "")

        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "records": records
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/flows/export")
def export_flows(
    table: str = Query("all", description="Table to search: 'all', 'ipfix', 'netflow9'"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    time_range: str = Query("all", description="Time range: '10m', '1h', '24h', '7d', 'all'"),
    start_time: Optional[str] = Query(None, description="Start UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    end_time: Optional[str] = Query(None, description="End UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    sort_by: str = Query("ts", description="Sort field: 'type', 'ts', 'exporter', 'src', 'sport', 'dst', 'dport', 'proto', 'packets', 'octets'"),
    sort_order: str = Query("desc", description="Sort order: 'asc', 'desc'"),
    group_by: Optional[str] = Query(None, description="Columns to group by, comma-separated")
):
    """Query flow records and stream them back as a CSV download."""
    import csv
    import io
    from fastapi.responses import StreamingResponse

    try:
        client = get_ch_client()

        where_clauses = []
        params = {}

        if src:
            where_clauses.append(build_ip_where_clause("src", src, params, "src"))
        if dst:
            where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
        if sport is not None:
            where_clauses.append("sport = %(sport)s")
            params["sport"] = sport
        if dport is not None:
            where_clauses.append("dport = %(dport)s")
            params["dport"] = dport
        if exporter:
            exp_parts = [e.strip() for e in exporter.split(",") if e.strip()]
            if exp_parts:
                where_clauses.append("exporter IN %(exporter_list)s")
                params["exporter_list"] = tuple(exp_parts)
        
        # Support multi-select protocols (comma-separated TCP,UDP)
        if proto:
            proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
            if proto_parts:
                proto_nums = []
                has_na = False
                for p in proto_parts:
                    if p.upper() == "N/A":
                        has_na = True
                        continue
                    p_num = get_proto_number(p)
                    if p_num is not None:
                        proto_nums.append(p_num)
                
                sub_clauses = []
                if proto_nums:
                    sub_clauses.append("protocol IN %(proto_nums)s")
                    params["proto_nums"] = tuple(proto_nums)
                if has_na:
                    sub_clauses.append("protocol IS NULL")
                
                if sub_clauses:
                    where_clauses.append("(" + " OR ".join(sub_clauses) + ")")

        # Handle time range (ClickHouse timestamps)
        if start_time or end_time:
            if start_time:
                where_clauses.append("ts >= %(start_time)s")
                params["start_time"] = start_time
            if end_time:
                where_clauses.append("ts <= %(end_time)s")
                params["end_time"] = end_time
        else:
            if time_range == "10m":
                where_clauses.append("ts >= now() - INTERVAL 10 MINUTE")
            elif time_range == "1h":
                where_clauses.append("ts >= now() - INTERVAL 1 HOUR")
            elif time_range == "24h":
                where_clauses.append("ts >= now() - INTERVAL 24 HOUR")
            elif time_range == "7d":
                where_clauses.append("ts >= now() - INTERVAL 7 DAY")

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        # Decide source table/UNION query
        tables = [t.strip().lower() for t in table.split(",") if t.strip()] if table else []
        has_ipfix = "ipfix" in tables or not tables or "all" in tables
        has_nf9 = "netflow9" in tables or not tables or "all" in tables

        if has_ipfix and not has_nf9:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix"
        elif has_nf9 and not has_ipfix:
            source_select = "SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9"
        elif has_ipfix and has_nf9:
            source_select = """
                SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix
                UNION ALL
                SELECT 'netflow9' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM netflow9
            """
        else:
            source_select = "SELECT 'ipfix' as type, id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts FROM ipfix WHERE 1=0"

        # Map sorting field to database column safely to prevent SQL injection
        sort_by_map = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol",
            "packets": "packets",
            "octets": "octets"
        }
        db_sort_by = sort_by_map.get(sort_by.lower(), "ts")
        db_sort_order = "DESC" if sort_order.lower() == "desc" else "ASC"

        # Check for dynamic aggregation / group by
        allowed_group_cols = {
            "type": "type",
            "ts": "ts",
            "exporter": "exporter",
            "src": "src",
            "sport": "sport",
            "dst": "dst",
            "dport": "dport",
            "proto": "protocol"
        }

        cols_to_group = []
        if group_by:
            cols_to_group = [allowed_group_cols[c] for c in group_by.split(",") if c in allowed_group_cols]

        if cols_to_group:
            # Adjust sorting fields for aggregated queries to resolve ambiguity in ClickHouse
            if db_sort_by == "packets":
                db_sort_by = "sum_packets"
            elif db_sort_by == "octets":
                db_sort_by = "sum_bytes"
            elif db_sort_by == "ts" and "ts" not in cols_to_group:
                db_sort_by = "max_ts"

            # Aggregate selected fields and pad rest with NULL
            select_list = []
            for col in cols_to_group:
                select_list.append(col)
            
            select_list.append("SUM(packets) as sum_packets")
            select_list.append("SUM(octets) as sum_bytes")
            
            if "ts" not in cols_to_group:
                select_list.append("MAX(ts) as max_ts")
            
            # Pad all unselected/ungrouped fields with NULL
            all_fields = {
                "type": "type",
                "exporter": "exporter",
                "src": "src",
                "sport": "sport",
                "dst": "dst",
                "dport": "dport",
                "protocol": "protocol"
            }
            for key, col in all_fields.items():
                if col not in cols_to_group:
                    select_list.append(f"CAST(NULL, 'Nullable(String)') as {col}" if col in ("type", "exporter", "src", "dst") else f"CAST(NULL, 'Nullable(UInt16)') as {col}")
            
            select_str = ", ".join(select_list)
            group_str = "GROUP BY " + ", ".join(cols_to_group)
            
            sql = f"""
                SELECT {select_str} FROM ({source_select})
                {where_str}
                {group_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT 100000
            """
        else:
            # Default unaggregated query
            sql = f"""
                SELECT * FROM ({source_select})
                {where_str}
                ORDER BY {db_sort_by} {db_sort_order}
                LIMIT 100000
            """

        # Execute data query
        result = client.query(sql, parameters=params)

        # Collect unique IPs to resolve domains from DNS cache
        ips_to_resolve = set()
        for row in result.result_rows:
            r = dict(zip(result.column_names, row))
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
        dns_map = get_dns_mappings(ips_to_resolve)

        # CSV generator
        def csv_generator():
            yield "\ufeff"
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Determine headers to display based on whether we are grouped or not
            # Exclude json_data from CSV export
            header = [col for col in result.column_names if col not in ("json_data", "id")]
            
            # Friendly headers mapping
            csv_headers = []
            for col in header:
                if col in ("ts", "max_ts"):
                    csv_headers.append("Timestamp (UTC)")
                elif col == "sum_packets":
                    csv_headers.append("Packets")
                elif col in ("sum_bytes", "octets"):
                    csv_headers.append("Bytes")
                elif col == "sport":
                    csv_headers.append("Source Port")
                elif col == "dport":
                    csv_headers.append("Destination Port")
                else:
                    csv_headers.append(col.capitalize())
            
            # Append resolved domains and protocol names
            if "src" in header:
                csv_headers.append("Source Domain")
            if "dst" in header:
                csv_headers.append("Destination Domain")
            if "sport" in header:
                csv_headers.append("Source Port Name")
            if "dport" in header:
                csv_headers.append("Destination Port Name")
            csv_headers.append("Protocol Name")

            writer.writerow(csv_headers)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)

            for row_vals in result.result_rows:
                r = dict(zip(result.column_names, row_vals))
                
                # Remap aggregated columns
                if "sum_packets" in r:
                    r["packets"] = r["sum_packets"]
                if "sum_bytes" in r:
                    r["octets"] = r["sum_bytes"]
                if "max_ts" in r:
                    r["ts"] = r["max_ts"]

                csv_row = []
                for col in header:
                    val = r.get(col, "")
                    if val is None:
                        val = ""
                    csv_row.append(str(val))
                
                # Add domain names (IP alias takes priority over DNS cache resolved domain)
                if "src" in r:
                    csv_row.append(resolve_ip_alias(r["src"]) or dns_map.get(r["src"], ""))
                if "dst" in r:
                    csv_row.append(resolve_ip_alias(r["dst"]) or dns_map.get(r["dst"], ""))
                
                # Add port names
                if "sport" in r:
                    csv_row.append(port_aliases_cache.get(r["sport"], ""))
                if "dport" in r:
                    csv_row.append(port_aliases_cache.get(r["dport"], ""))
                
                # Add protocol friendly name
                if "protocol" in r and r["protocol"] is not None:
                    proto_name = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})")
                else:
                    proto_name = "N/A"
                csv_row.append(proto_name)

                writer.writerow(csv_row)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)

        filename = f"flow_export_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
        return StreamingResponse(
            csv_generator(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename={filename}"
            }
        )

    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/stats")
def get_stats(
    table: str = Query("all", description="Table to search: 'all', 'ipfix', 'netflow9'"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    time_range: str = Query("24h", description="Time range for stats: '1h', '24h', '7d', 'all'"),
    start_time: Optional[str] = Query(None, description="Start UTC timestamp (YYYY-MM-DD HH:MM:SS)"),
    end_time: Optional[str] = Query(None, description="End UTC timestamp (YYYY-MM-DD HH:MM:SS)")
):
    """Get dashboard overview statistics and chart data."""
    try:
        client = get_ch_client()

        # Build dynamic where clauses
        where_clauses = []
        params = {}

        if exporter:
            exp_parts = [e.strip() for e in exporter.split(",") if e.strip()]
            if exp_parts:
                where_clauses.append("exporter IN %(exporter_list)s")
                params["exporter_list"] = tuple(exp_parts)
        if src:
            where_clauses.append(build_ip_where_clause("src", src, params, "src"))
        if dst:
            where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
        if sport is not None:
            where_clauses.append("sport = %(sport)s")
            params["sport"] = sport
        if dport is not None:
            where_clauses.append("dport = %(dport)s")
            params["dport"] = dport

        # Handle Protocol checklist
        if proto:
            p_list = [p.strip() for p in proto.split(",") if p.strip()]
            if p_list:
                proto_nums = []
                has_na = False
                for p in p_list:
                    if p.upper() == "N/A":
                        has_na = True
                        continue
                    p_num = get_proto_number(p)
                    if p_num is not None:
                        proto_nums.append(p_num)
                
                sub_clauses = []
                if proto_nums:
                    sub_clauses.append("protocol IN %(proto_nums)s")
                    params["proto_nums"] = tuple(proto_nums)
                if has_na:
                    sub_clauses.append("protocol IS NULL")
                
                if sub_clauses:
                    where_clauses.append("(" + " OR ".join(sub_clauses) + ")")

        # Handle time range (ClickHouse timestamps)
        if start_time or end_time:
            if start_time:
                where_clauses.append("ts >= %(start_time)s")
                params["start_time"] = start_time
            if end_time:
                where_clauses.append("ts <= %(end_time)s")
                params["end_time"] = end_time
        else:
            if time_range == "1h":
                where_clauses.append("ts >= now() - INTERVAL 1 HOUR")
            elif time_range == "24h":
                where_clauses.append("ts >= now() - INTERVAL 24 HOUR")
            elif time_range == "7d":
                where_clauses.append("ts >= now() - INTERVAL 7 DAY")

        where_str = ""
        if where_clauses:
            where_str = "WHERE " + " AND ".join(where_clauses)

        # Decide source table/UNION query
        tables = [t.strip().lower() for t in table.split(",") if t.strip()] if table else []
        has_ipfix = "ipfix" in tables or not tables or "all" in tables
        has_nf9 = "netflow9" in tables or not tables or "all" in tables

        if has_ipfix and not has_nf9:
            combined_flows = f"SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix {where_str}"
        elif has_nf9 and not has_ipfix:
            combined_flows = f"SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM netflow9 {where_str}"
        elif has_ipfix and has_nf9:
            combined_flows = f"""
                SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix {where_str}
                UNION ALL
                SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM netflow9 {where_str}
            """
        else:
            combined_flows = f"SELECT exporter, src, dst, sport, dport, packets, octets, protocol, ts FROM ipfix WHERE 1=0"

        # 1. Overall Totals
        res = client.query(f"SELECT COUNT() as total_flows, SUM(packets) as total_packets, SUM(octets) as total_bytes FROM ({combined_flows})", parameters=params)
        totals = dict(zip(res.column_names, res.result_rows[0]))
        total_flows = totals["total_flows"] or 0
        total_packets = totals["total_packets"] or 0
        total_bytes = totals["total_bytes"] or 0

        # 2. Top Sources by bytes
        res = client.query(f"""
            SELECT src, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM ({combined_flows})
            GROUP BY src
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_sources = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 3. Top Destinations by bytes
        res = client.query(f"""
            SELECT dst, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM ({combined_flows})
            GROUP BY dst
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_destinations = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 4. Top Exporters
        res = client.query(f"""
            SELECT exporter, SUM(octets) as bytes, COUNT() as flows
            FROM ({combined_flows})
            GROUP BY exporter
            ORDER BY flows DESC
            LIMIT 5
        """, parameters=params)
        top_exporters = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 5. Protocols share
        res = client.query(f"""
            SELECT protocol, COUNT() as count, SUM(octets) as bytes
            FROM ({combined_flows})
            GROUP BY protocol
            ORDER BY count DESC
        """, parameters=params)
        raw_protocols = [dict(zip(res.column_names, r)) for r in res.result_rows]
        protocols = []
        for p in raw_protocols:
            p_num = p["protocol"]
            p_name = PROTO_NAME_MAP.get(p_num, f"OTHER ({p_num})" if p_num is not None else "N/A")
            protocols.append({
                "protocol": p_num,
                "name": p_name,
                "count": p["count"],
                "bytes": p["bytes"] or 0
            })

        # 6. Traffic over time
        if start_time and end_time:
            try:
                from datetime import datetime as dt
                d1 = dt.strptime(start_time, "%Y-%m-%d %H:%M:%S")
                d2 = dt.strptime(end_time, "%Y-%m-%d %H:%M:%S")
                diff = (d2 - d1).total_seconds()
                if diff < 7200: # < 2 hours
                    time_format = "%Y-%m-%d %H:%M:00"
                    ch_group_fn = "toStartOfMinute(ts + INTERVAL 8 HOUR)"
                elif diff < 172800: # < 48 hours
                    time_format = "%Y-%m-%d %H:00:00"
                    ch_group_fn = "toStartOfHour(ts + INTERVAL 8 HOUR)"
                else:
                    time_format = "%Y-%m-%d"
                    ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
            except Exception:
                time_format = "%Y-%m-%d"
                ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
        else:
            if time_range == "1h":
                time_format = "%Y-%m-%d %H:%M:00"
                ch_group_fn = "toStartOfMinute(ts + INTERVAL 8 HOUR)"
            elif time_range == "24h":
                time_format = "%Y-%m-%d %H:00:00"
                ch_group_fn = "toStartOfHour(ts + INTERVAL 8 HOUR)"
            elif time_range == "7d":
                time_format = "%Y-%m-%d"
                ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
            else:
                time_format = "%Y-%m-%d"
                ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"

        res = client.query(f"""
            SELECT {ch_group_fn} as time_bin, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM ({combined_flows})
            GROUP BY time_bin
            ORDER BY time_bin ASC
        """, parameters=params)
        
        traffic_over_time = []
        for r_row in res.result_rows:
            r = dict(zip(res.column_names, r_row))
            tb = r["time_bin"]
            if isinstance(tb, datetime):
                r["time_bin"] = tb.strftime(time_format)
            traffic_over_time.append(r)

        # 7. Top Source Ports by bytes
        res = client.query(f"""
            SELECT sport, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM ({combined_flows})
            WHERE sport IS NOT NULL
            GROUP BY sport
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_source_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 8. Top Destination Ports by bytes
        res = client.query(f"""
            SELECT dport, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM ({combined_flows})
            WHERE dport IS NOT NULL
            GROUP BY dport
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_destination_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # Collect unique IPs in stats
        stats_ips = set()
        for item in top_sources:
            if item.get("src"):
                stats_ips.add(item["src"])
        for item in top_destinations:
            if item.get("dst"):
                stats_ips.add(item["dst"])
        
        # Get DNS and IP Aliases mappings in batch
        stats_dns_map = get_dns_mappings(stats_ips)
        alias_map = resolve_ip_aliases_batch(stats_ips)
        
        # Attach resolved domains and aliases
        for item in top_sources:
            ip = item.get("src")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")
        for item in top_destinations:
            ip = item.get("dst")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")

        # Attach port aliases
        for item in top_source_ports:
            item["port_name"] = port_aliases_cache.get(item.get("sport"), "") if item.get("sport") is not None else ""
        for item in top_destination_ports:
            item["port_name"] = port_aliases_cache.get(item.get("dport"), "") if item.get("dport") is not None else ""

        return {
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_exporters": top_exporters,
            "protocols": protocols,
            "traffic_over_time": traffic_over_time,
            "top_source_ports": top_source_ports,
            "top_destination_ports": top_destination_ports
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/flows/delete")
def delete_flows_before(before: str = Query(..., description="Delete data before this datetime, format: YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")):
    try:
        cutoff_dt = None
        for fmt in ("%Y-%m-%d", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
            try:
                cutoff_dt = datetime.strptime(before, fmt)
                break
            except ValueError:
                continue
        
        if not cutoff_dt:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD or YYYY-MM-DD HH:MM:SS")
            
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        client = get_ch_client()
        client.command("ALTER TABLE ipfix DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        client.command("ALTER TABLE netflow9 DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        
        return {"status": "success", "message": f"Successfully queued deletion mutation in ClickHouse for records older than {cutoff_str}."}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ports/aliases")
def get_port_aliases():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT port, name FROM port_aliases ORDER BY port ASC")
        rows = cur.fetchall()
        conn.close()
        return [{"port": r["port"], "name": r["name"]} for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ports/aliases")
def set_port_alias(port: int, name: str):
    name = name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Name cannot be empty")
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("INSERT OR REPLACE INTO port_aliases (port, name) VALUES (?, ?)", (port, name))
        conn.commit()
        conn.close()
        load_port_aliases() # Refresh cache
        return {"status": "success", "message": f"Port {port} named as {name}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/ports/aliases/{port}")
def delete_port_alias(port: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM port_aliases WHERE port = ?", (port,))
        conn.commit()
        conn.close()
        load_port_aliases() # Refresh cache
        return {"status": "success", "message": f"Deleted alias for port {port}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/ips/aliases")
def get_ip_aliases(
    limit: int = Query(25, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    q: Optional[str] = Query(None)
):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        where_clause = ""
        params = []
        if q:
            q_clean = f"%{q.strip()}%"
            where_clause = "WHERE ip LIKE ? OR name LIKE ?"
            params = [q_clean, q_clean]
            
        cur.execute(f"SELECT COUNT(*) FROM ip_aliases {where_clause}", params)
        total_count = cur.fetchone()[0]
        
        params.extend([limit, offset])
        cur.execute(f"SELECT ip, name FROM ip_aliases {where_clause} ORDER BY ip ASC LIMIT ? OFFSET ?", params)
        rows = cur.fetchall()
        conn.close()
        
        return {
            "total": total_count,
            "limit": limit,
            "offset": offset,
            "records": [{"ip": r["ip"], "name": r["name"]} for r in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/ips/aliases")
def set_ip_alias(ip: str, name: str):
    ip = ip.strip()
    name = name.strip()
    if not ip or not name:
        raise HTTPException(status_code=400, detail="IP and Name cannot be empty")
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        start_ip, end_ip, prefix_len = None, None, None
        try:
            if "/" in ip:
                net = ipaddress.ip_network(ip, strict=False)
                start_ip = ip_to_hex(net.network_address)
                end_ip = ip_to_hex(net.broadcast_address)
                prefix_len = net.prefixlen
            else:
                ip_obj = ipaddress.ip_address(ip)
                start_ip = ip_to_hex(ip_obj)
                end_ip = start_ip
                prefix_len = 32 if ip_obj.version == 4 else 128
        except Exception:
            pass
            
        cur.execute("INSERT OR REPLACE INTO ip_aliases (ip, name, start_ip, end_ip, prefix_len) VALUES (?, ?, ?, ?, ?)",
                    (ip, name, start_ip, end_ip, prefix_len))
        conn.commit()
        conn.close()
        load_ip_aliases() # Refresh cache
        return {"status": "success", "message": f"IP {ip} named as {name}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/ips/aliases/{ip:path}")
def delete_ip_alias(ip: str):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM ip_aliases WHERE ip = ?", (ip,))
        conn.commit()
        conn.close()
        load_ip_aliases() # Refresh cache
        return {"status": "success", "message": f"Deleted alias for IP {ip}"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/aliases/export")
def export_aliases():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get IP aliases
        cur.execute("SELECT ip, name FROM ip_aliases ORDER BY ip ASC")
        ip_rows = cur.fetchall()
        ips = [{"ip": r["ip"], "name": r["name"]} for r in ip_rows]
        
        # Get Port aliases
        cur.execute("SELECT port, name FROM port_aliases ORDER BY port ASC")
        port_rows = cur.fetchall()
        ports = [{"port": r["port"], "name": r["name"]} for r in port_rows]
        
        conn.close()
        return {
            "ip_aliases": ips,
            "port_aliases": ports
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/aliases/import")
def import_aliases(payload: Dict[str, Any]):
    ip_aliases = payload.get("ip_aliases", [])
    port_aliases = payload.get("port_aliases", [])
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        imported_ips = 0
        imported_ports = 0
        
        # Insert IP aliases
        for item in ip_aliases:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            name = item.get("name")
            if not ip or not name:
                continue
            ip = str(ip).strip()
            name = str(name).strip()
            if ip and name:
                start_ip, end_ip, prefix_len = None, None, None
                try:
                    if "/" in ip:
                        net = ipaddress.ip_network(ip, strict=False)
                        start_ip = ip_to_hex(net.network_address)
                        end_ip = ip_to_hex(net.broadcast_address)
                        prefix_len = net.prefixlen
                    else:
                        ip_obj = ipaddress.ip_address(ip)
                        start_ip = ip_to_hex(ip_obj)
                        end_ip = start_ip
                        prefix_len = 32 if ip_obj.version == 4 else 128
                except Exception:
                    pass
                cur.execute("INSERT OR REPLACE INTO ip_aliases (ip, name, start_ip, end_ip, prefix_len) VALUES (?, ?, ?, ?, ?)",
                            (ip, name, start_ip, end_ip, prefix_len))
                imported_ips += 1
                
        # Insert Port aliases
        for item in port_aliases:
            if not isinstance(item, dict):
                continue
            port = item.get("port")
            name = item.get("name")
            if port is None or not name:
                continue
            try:
                port_val = int(port)
                if port_val < 1 or port_val > 65535:
                    continue
            except ValueError:
                continue
            name = str(name).strip()
            if name:
                cur.execute("INSERT OR REPLACE INTO port_aliases (port, name) VALUES (?, ?)", (port_val, name))
                imported_ports += 1
                
        conn.commit()
        conn.close()
        
        # Refresh in-memory caches
        load_ip_aliases()
        load_port_aliases()
        
        return {
            "status": "success",
            "message": f"Successfully imported {imported_ips} IP aliases and {imported_ports} Port aliases (overwrote duplicate keys)."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/aliases/clear")
def clear_all_aliases():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM ip_aliases")
        cur.execute("DELETE FROM port_aliases")
        conn.commit()
        conn.close()
        
        # Refresh in-memory caches
        load_ip_aliases()
        load_port_aliases()
        
        return {
            "status": "success",
            "message": "All custom IP and Port aliases cleared successfully."
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Helper validation functions for Audit System
def validate_ip_or_cidr(ip_str: str) -> bool:
    if not ip_str:
        return True
    val = ip_str.strip().lower()
    if val in ("internal", "external"):
        return True
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(ip_str, strict=False)
        return True
    except ValueError:
        pass
    return False

def validate_port_or_range(port_str: str) -> bool:
    if not port_str:
        return True
    if '-' in port_str:
        parts = port_str.split('-')
        if len(parts) != 2:
            return False
        try:
            start = int(parts[0].strip())
            end = int(parts[1].strip())
            return 0 <= start <= 65535 and 0 <= end <= 65535 and start <= end
        except ValueError:
            return False
    else:
        try:
            val = int(port_str.strip())
            return 0 <= val <= 65535
        except ValueError:
            return False

INTRANET_NETWORKS = [
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("10.0.0.0/8")
]

def is_internal_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    for net in INTRANET_NETWORKS:
        if ip_obj in net:
            return True
    return False

def parse_rule_criteria(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    parsed = []
    for r in rules:
        rule_obj = {
            "id": r["id"],
            "ip_raw": r["ip"],
            "port_raw": r["port"],
            "flag": r["flag"],
            "ip_obj": None,
            "port_obj": None
        }
        if r["ip"]:
            ip_val = r["ip"].strip().lower()
            if ip_val in ("internal", "external"):
                rule_obj["ip_obj"] = ip_val
            else:
                try:
                    if '/' in r["ip"]:
                        rule_obj["ip_obj"] = ipaddress.ip_network(r["ip"], strict=False)
                    else:
                        rule_obj["ip_obj"] = ipaddress.ip_address(r["ip"])
                except Exception:
                    pass
        if r["port"]:
            if '-' in r["port"]:
                parts = r["port"].split('-')
                rule_obj["port_obj"] = (int(parts[0]), int(parts[1]))
            else:
                rule_obj["port_obj"] = int(r["port"])
        parsed.append(rule_obj)
    return parsed

def check_flow_match(flow: Dict[str, Any], parsed_rules: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    flow_src_ip = None
    flow_dst_ip = None
    try:
        flow_src_ip = ipaddress.ip_address(flow.get("src", ""))
    except Exception:
        pass
    try:
        flow_dst_ip = ipaddress.ip_address(flow.get("dst", ""))
    except Exception:
        pass
        
    flow_sport = flow.get("sport")
    flow_dport = flow.get("dport")
    
    for rule in parsed_rules:
        ip_matched = True
        port_matched = True
        
        # IP match
        if rule["ip_obj"]:
            ip_matched = False
            rule_ip = rule["ip_obj"]
            # Check src IP
            if flow_src_ip:
                if rule_ip == "internal":
                    if is_internal_ip(flow_src_ip):
                        ip_matched = True
                elif rule_ip == "external":
                    if not is_internal_ip(flow_src_ip):
                        ip_matched = True
                elif isinstance(rule_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if flow_src_ip == rule_ip:
                        ip_matched = True
                else: # Network
                    if flow_src_ip in rule_ip:
                        ip_matched = True
            # Check dst IP
            if not ip_matched and flow_dst_ip:
                if rule_ip == "internal":
                    if is_internal_ip(flow_dst_ip):
                        ip_matched = True
                elif rule_ip == "external":
                    if not is_internal_ip(flow_dst_ip):
                        ip_matched = True
                elif isinstance(rule_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
                    if flow_dst_ip == rule_ip:
                        ip_matched = True
                else: # Network
                    if flow_dst_ip in rule_ip:
                        ip_matched = True
                        
        # Port match
        if rule["port_obj"]:
            port_matched = False
            # Check sport
            if flow_sport is not None:
                if isinstance(rule["port_obj"], tuple):
                    if rule["port_obj"][0] <= flow_sport <= rule["port_obj"][1]:
                        port_matched = True
                else:
                    if flow_sport == rule["port_obj"]:
                        port_matched = True
            # Check dport
            if not port_matched and flow_dport is not None:
                if isinstance(rule["port_obj"], tuple):
                    if rule["port_obj"][0] <= flow_dport <= rule["port_obj"][1]:
                        port_matched = True
                else:
                    if flow_dport == rule["port_obj"]:
                        port_matched = True
                        
        if ip_matched and port_matched:
            return rule
            
    return None

def run_traffic_audit(start_time_str: Optional[str] = None) -> Dict[str, Any]:
    print("[Audit] Starting traffic audit...", flush=True)
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, ip, port, flag FROM audit_rules")
        rules = [dict(row) for row in cur.fetchall()]
        
        if not rules:
            cur.execute("INSERT INTO audit_logs (status, records_matched, message) VALUES (?, ?, ?)", 
                        ("skipped", 0, "No audit rules configured. Skip matching."))
            conn.commit()
            conn.close()
            return {"status": "skipped", "records_matched": 0, "message": "No audit rules configured."}
            
        parsed_rules = parse_rule_criteria(rules)
        
        if start_time_str:
            try:
                if 'T' in start_time_str:
                    try:
                        # Parsing from datetime-local ISO format: YYYY-MM-DDTHH:MM
                        # Convert user's local UTC+8 time input to UTC naive datetime
                        dt_local = datetime.fromisoformat(start_time_str)
                        last_run_dt = dt_local - timedelta(hours=8)
                    except Exception:
                        last_run_dt = datetime.fromisoformat(start_time_str.replace('Z', '+00:00')).astimezone(timezone.utc).replace(tzinfo=None)
                else:
                    last_run_dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S")
            except Exception:
                last_run_dt = datetime.utcnow() - timedelta(days=7)
        else:
            cur.execute("SELECT run_ts FROM audit_logs WHERE status = 'success' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                last_run_str = row["run_ts"]
                try:
                    last_run_dt = datetime.strptime(last_run_str, "%Y-%m-%d %H:%M:%S")
                except ValueError:
                    last_run_dt = datetime.utcnow() - timedelta(days=7)
            else:
                last_run_dt = datetime.utcnow() - timedelta(days=7)
            
        current_run_dt = datetime.now(timezone.utc)
        last_run_str = last_run_dt.strftime("%Y-%m-%d %H:%M:%S")
        current_run_str = current_run_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"[Audit] Audit range: {last_run_str} to {current_run_str} (UTC)", flush=True)
        
        client = get_ch_client()
        tables = ["ipfix", "netflow9"]
        all_matched_records = []
        
        for table in tables:
            query = f"""
                SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts
                FROM {table}
                WHERE ts >= %(start)s AND ts < %(end)s
            """
            result = client.query(query, parameters={"start": last_run_str, "end": current_run_str})
            column_names = result.column_names
            rows = result.result_rows
            
            for row_vals in rows:
                flow = dict(zip(column_names, row_vals))
                matching_rule = check_flow_match(flow, parsed_rules)
                if matching_rule:
                    if isinstance(flow.get("ts"), datetime):
                        flow["ts"] = flow["ts"].replace(tzinfo=timezone.utc)
                    flow["rule_ip"] = matching_rule["ip_raw"]
                    flow["rule_port"] = matching_rule["port_raw"]
                    flow["match_flag"] = matching_rule["flag"]
                    flow["match_ts"] = current_run_dt
                    all_matched_records.append(flow)
                    
        if all_matched_records:
            insert_data = []
            for r in all_matched_records:
                insert_data.append([
                    r["id"],
                    r["exporter"],
                    r["proto"],
                    r["src"],
                    r["dst"],
                    r.get("sport", 0),
                    r.get("dport", 0),
                    r.get("packets", 0),
                    r.get("octets", 0),
                    r.get("protocol"),
                    r["json_data"],
                    r["ts"],
                    r["rule_ip"],
                    r["rule_port"],
                    r["match_flag"],
                    r["match_ts"]
                ])
                
            client.insert("matched_flows", insert_data, column_names=[
                "id", "exporter", "proto", "src", "dst", "sport", "dport", "packets", "octets", "protocol", "json_data", "ts", "rule_ip", "rule_port", "match_flag", "match_ts"
            ])
            
        cur.execute("INSERT INTO audit_logs (run_ts, status, records_matched, message) VALUES (?, ?, ?, ?)",
                    (current_run_str, "success", len(all_matched_records), f"Audit completed. Found {len(all_matched_records)} matches."))
        conn.commit()
        conn.close()
        
        print(f"[Audit] Audit success. Matched and saved {len(all_matched_records)} records.", flush=True)
        return {"status": "success", "records_matched": len(all_matched_records), "message": f"Audit completed. {len(all_matched_records)} records matched."}
        
    except Exception as e:
        print(f"[Audit] Audit failed: {e}", flush=True)
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("INSERT INTO audit_logs (status, records_matched, message) VALUES (?, ?, ?)",
                        ("failed", 0, str(e)))
            conn.commit()
            conn.close()
        except Exception as sqlite_err:
            print(f"[Audit] Failed to log failure in SQLite: {sqlite_err}", flush=True)
        return {"status": "failed", "records_matched": 0, "message": str(e)}

def audit_scheduler_loop():
    print("[Audit] Background daily scheduler thread started.", flush=True)
    try:
        time.sleep(30)
    except Exception:
        pass
        
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT run_ts FROM audit_logs WHERE status = 'success' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            conn.close()
            
            should_run = False
            if row:
                last_run_str = row[0]
                last_run_dt = datetime.strptime(last_run_str, "%Y-%m-%d %H:%M:%S")
                if datetime.utcnow() - last_run_dt >= timedelta(hours=24):
                    should_run = True
            else:
                should_run = True
                
            if should_run:
                run_traffic_audit()
        except Exception as sched_err:
            print(f"[Audit] Scheduler loop error: {sched_err}", flush=True)
            
        time.sleep(3600)

class AuditRuleCreate(BaseModel):
    ip: Optional[str] = None
    port: Optional[str] = None
    flag: str

@app.get("/api/audit/rules")
def get_audit_rules():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, ip, port, flag, created_at FROM audit_rules ORDER BY id DESC")
        rules = [dict(row) for row in cur.fetchall()]
        conn.close()
        for rule in rules:
            ip = rule.get("ip")
            rule["ip_alias"] = resolve_ip_alias(ip) if ip else ""
        return rules
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/rules/export")
def export_audit_rules():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT ip, port, flag FROM audit_rules ORDER BY id ASC")
        rows = cur.fetchall()
        conn.close()
        return [{"ip": r["ip"], "port": r["port"], "flag": r["flag"]} for r in rows]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audit/rules/import")
def import_audit_rules(payload: List[Dict[str, Any]]):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        imported = 0
        for item in payload:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            port = item.get("port")
            flag = item.get("flag")
            
            # Basic validation
            if flag not in ("watch", "anomaly"):
                continue
                
            ip_val = str(ip).strip() if ip is not None else None
            port_val = str(port).strip() if port is not None else None
            
            if not ip_val and not port_val:
                continue
                
            cur.execute("""
                INSERT OR REPLACE INTO audit_rules (ip, port, flag)
                VALUES (?, ?, ?)
            """, (ip_val, port_val, flag))
            imported += 1
            
        conn.commit()
        conn.close()
        return {"status": "success", "message": f"Successfully imported {imported} audit rules."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audit/rules")
def create_audit_rule(rule: AuditRuleCreate):
    ip_val = rule.ip.strip() if rule.ip else None
    port_val = rule.port.strip() if rule.port else None
    flag_val = rule.flag.strip().lower()
    
    if flag_val not in ("watch", "anomaly"):
        raise HTTPException(status_code=400, detail="Flag must be 'watch' or 'anomaly'")
        
    if not ip_val and not port_val:
        raise HTTPException(status_code=400, detail="At least one of IP or Port must be provided.")
        
    if ip_val and not validate_ip_or_cidr(ip_val):
        raise HTTPException(status_code=400, detail="Invalid IP or CIDR address format.")
        
    if port_val and not validate_port_or_range(port_val):
        raise HTTPException(status_code=400, detail="Invalid Port or Port range format. Use e.g. '80' or '80-443'")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT id FROM audit_rules WHERE (ip IS ? OR ip = ?) AND (port IS ? OR port = ?)", 
                    (ip_val, ip_val, port_val, port_val))
        if cur.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="Rule already exists.")
            
        cur.execute("INSERT INTO audit_rules (ip, port, flag) VALUES (?, ?, ?)", (ip_val, port_val, flag_val))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Audit rule created successfully."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/rules")
def clear_audit_rules():
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_rules")
        conn.commit()
        conn.close()
        return {"status": "success", "message": "All audit rules cleared successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/rules/{rule_id}")
def delete_audit_rule(rule_id: int):
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("DELETE FROM audit_rules WHERE id = ?", (rule_id,))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Audit rule deleted successfully."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

class AuditRunRequest(BaseModel):
    start_time: Optional[str] = None

@app.post("/api/audit/run")
def trigger_audit(payload: Optional[AuditRunRequest] = None):
    start_time_str = payload.start_time if payload else None
    result = run_traffic_audit(start_time_str)
    if result["status"] == "success":
        return result
    else:
        raise HTTPException(status_code=500, detail=result["message"])

@app.get("/api/audit/status")
def get_audit_status():
    def to_utc8_str(utc_dt_str: str) -> str:
        if not utc_dt_str or utc_dt_str == "Never":
            return "Never"
        try:
            utc_dt_str = utc_dt_str.replace('T', ' ')
            dt = datetime.strptime(utc_dt_str, "%Y-%m-%d %H:%M:%S")
            utc8_dt = dt + timedelta(hours=8)
            return utc8_dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return utc_dt_str

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        # Get last run log (success or failed)
        cur.execute("SELECT run_ts, status, records_matched, message FROM audit_logs ORDER BY id DESC LIMIT 1")
        last_log = cur.fetchone()
        
        # Get last success run to calculate next run
        cur.execute("SELECT run_ts FROM audit_logs WHERE status = 'success' ORDER BY id DESC LIMIT 1")
        last_success = cur.fetchone()
        
        conn.close()
        
        last_run_utc8 = "Never"
        next_run_utc8 = "Immediately"
        status = "none"
        records_matched = 0
        message = "No audit has run yet."
        
        if last_log:
            last_run_utc8 = to_utc8_str(last_log["run_ts"])
            status = last_log["status"]
            records_matched = last_log["records_matched"]
            message = last_log["message"]
            
        if last_success:
            utc_str = last_success["run_ts"].replace('T', ' ')
            dt = datetime.strptime(utc_str, "%Y-%m-%d %H:%M:%S")
            next_dt = dt + timedelta(hours=24)
            next_run_utc8 = to_utc8_str(next_dt.strftime("%Y-%m-%d %H:%M:%S"))
            
        return {
            "run_ts": last_run_utc8,
            "next_run_ts": next_run_utc8,
            "status": status,
            "records_matched": records_matched,
            "message": message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches/stats")
def get_audit_matches_stats(
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    flag: Optional[str] = Query(None)
):
    try:
        client = get_ch_client()
        where_clauses = []
        params = {}
        
        if src:
            where_clauses.append(build_ip_where_clause("src", src, params, "src"))
        if dst:
            where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
        if sport is not None:
            where_clauses.append("sport = %(sport)s")
            params["sport"] = sport
        if dport is not None:
            where_clauses.append("dport = %(dport)s")
            params["dport"] = dport
        if port is not None:
            where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
            params["port"] = port
        if flag:
            where_clauses.append("match_flag = %(flag)s")
            params["flag"] = flag.strip().lower()
            
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        # 1. Total flows/packets/bytes
        res = client.query(f"SELECT COUNT() as total_flows, SUM(packets) as total_packets, SUM(octets) as total_bytes FROM matched_flows {where_sql}", parameters=params)
        totals = dict(zip(res.column_names, res.result_rows[0]))
        total_flows = totals["total_flows"] or 0
        total_packets = totals["total_packets"] or 0
        total_bytes = totals["total_bytes"] or 0

        # 2. Top Sources
        res = client.query(f"""
            SELECT src, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM matched_flows
            {where_sql}
            GROUP BY src
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_sources = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 3. Top Destinations
        res = client.query(f"""
            SELECT dst, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM matched_flows
            {where_sql}
            GROUP BY dst
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_destinations = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 4. Top Source Ports
        res = client.query(f"""
            SELECT sport, SUM(octets) as bytes, COUNT() as flows
            FROM matched_flows
            {where_sql}
            WHERE sport IS NOT NULL
            GROUP BY sport
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_source_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 5. Top Destination Ports
        res = client.query(f"""
            SELECT dport, SUM(octets) as bytes, COUNT() as flows
            FROM matched_flows
            {where_sql}
            WHERE dport IS NOT NULL
            GROUP BY dport
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_destination_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 5b. Top Ports (Overall union)
        res = client.query(f"""
            SELECT port, SUM(octets) as bytes, COUNT() as flows
            FROM (
                SELECT sport as port, octets FROM matched_flows {where_sql} WHERE sport IS NOT NULL
                UNION ALL
                SELECT dport as port, octets FROM matched_flows {where_sql} WHERE dport IS NOT NULL
            )
            GROUP BY port
            ORDER BY bytes DESC
            LIMIT 10
        """, parameters=params)
        top_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 6. Protocols Share
        res = client.query(f"""
            SELECT proto as name, COUNT() as count, SUM(octets) as bytes
            FROM matched_flows
            {where_sql}
            GROUP BY name
            ORDER BY count DESC
        """, parameters=params)
        protocols = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 6b. IP Protocols Share (TCP, UDP, etc.)
        res = client.query(f"""
            SELECT protocol as name_num, COUNT() as count, SUM(octets) as bytes
            FROM matched_flows
            {where_sql}
            GROUP BY name_num
            ORDER BY count DESC
        """, parameters=params)
        ip_protocols = []
        for r in res.result_rows:
            p_num = r[0]
            p_name = PROTO_NAME_MAP.get(p_num, f"UNKNOWN ({p_num})" if p_num is not None else "N/A")
            ip_protocols.append({
                "protocol": p_num,
                "name": p_name,
                "count": r[1],
                "bytes": r[2]
            })

        # 7. Flags Share
        res = client.query(f"""
            SELECT match_flag as name, COUNT() as count, SUM(octets) as bytes
            FROM matched_flows
            {where_sql}
            GROUP BY name
            ORDER BY count DESC
        """, parameters=params)
        flags = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 8. Traffic over time
        range_res = client.query(f"SELECT min(ts), max(ts) FROM matched_flows {where_sql}", parameters=params)
        min_ts, max_ts = range_res.result_rows[0]
        
        time_format = "%Y-%m-%d"
        ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
        if min_ts and max_ts:
            diff_secs = (max_ts - min_ts).total_seconds()
            if diff_secs < 172800: # < 48 hours
                time_format = "%Y-%m-%d %H:00"
                ch_group_fn = "toStartOfHour(ts + INTERVAL 8 HOUR)"
                
        res = client.query(f"""
            SELECT {ch_group_fn} as time_bin, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM matched_flows
            {where_sql}
            GROUP BY time_bin
            ORDER BY time_bin ASC
        """, parameters=params)
        
        traffic_over_time = []
        for r_row in res.result_rows:
            r = dict(zip(res.column_names, r_row))
            tb = r["time_bin"]
            if isinstance(tb, datetime):
                r["time_bin"] = tb.strftime(time_format)
            traffic_over_time.append(r)

        # Resolve IPs
        stats_ips = set()
        for item in top_sources:
            if item.get("src"):
                stats_ips.add(item["src"])
        for item in top_destinations:
            if item.get("dst"):
                stats_ips.add(item["dst"])
        # Get DNS and IP Aliases mappings in batch
        stats_dns_map = get_dns_mappings(stats_ips)
        alias_map = resolve_ip_aliases_batch(stats_ips)
        for item in top_sources:
            ip = item.get("src")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")
        for item in top_destinations:
            ip = item.get("dst")
            item["domain"] = alias_map.get(ip) or stats_dns_map.get(ip, "")

        # Resolve Ports
        for item in top_source_ports:
            sport = item.get("sport")
            item["port_name"] = port_aliases_cache.get(sport, "") if sport is not None else ""
        for item in top_destination_ports:
            dport = item.get("dport")
            item["port_name"] = port_aliases_cache.get(dport, "") if dport is not None else ""
        for item in top_ports:
            port = item.get("port")
            item["port_name"] = port_aliases_cache.get(port, "") if port is not None else ""

        return {
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_source_ports": top_source_ports,
            "top_destination_ports": top_destination_ports,
            "top_ports": top_ports,
            "protocols": protocols,
            "ip_protocols": ip_protocols,
            "flags": flags,
            "traffic_over_time": traffic_over_time
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches")
def get_audit_matches(
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    flag: Optional[str] = Query(None),
    sort_by: str = Query("match_ts"),
    sort_order: str = Query("desc")
):
    try:
        client = get_ch_client()
        where_clauses = []
        params = {}
        
        if src:
            where_clauses.append(build_ip_where_clause("src", src, params, "src"))
        if dst:
            where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
        if sport is not None:
            where_clauses.append("sport = %(sport)s")
            params["sport"] = sport
        if dport is not None:
            where_clauses.append("dport = %(dport)s")
            params["dport"] = dport
        if port is not None:
            where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
            params["port"] = port
        if flag:
            where_clauses.append("match_flag = %(flag)s")
            params["flag"] = flag.strip().lower()
            
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        count_query = f"SELECT count() FROM matched_flows {where_sql}"
        count_result = client.query(count_query, parameters=params)
        total_records = count_result.result_rows[0][0]
        
        # Validate sort field to prevent SQL injection
        allowed_cols = {
            "match_ts", "ts", "match_flag", "rule_ip", "rule_port",
            "src", "sport", "dst", "dport", "proto", "packets", "octets"
        }
        if sort_by not in allowed_cols:
            sort_by = "match_ts"
            
        order_sql = "DESC" if sort_order.lower() == "desc" else "ASC"
        
        query = f"""
            SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts, rule_ip, rule_port, match_flag, match_ts
            FROM matched_flows
            {where_sql}
            ORDER BY {sort_by} {order_sql}, ts DESC
            LIMIT %(limit)s OFFSET %(offset)s
        """
        params["limit"] = limit
        params["offset"] = offset
        
        data_result = client.query(query, parameters=params)
        column_names = data_result.column_names
        records = []
        ips_to_resolve = set()
        
        for row_vals in data_result.result_rows:
            r = dict(zip(column_names, row_vals))
            if isinstance(r["ts"], datetime):
                r["ts"] = r["ts"].strftime("%Y-%m-%d %H:%M:%S")
            if isinstance(r["match_ts"], datetime):
                r["match_ts"] = r["match_ts"].strftime("%Y-%m-%d %H:%M:%S")
            records.append(r)
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
                
        # Get DNS and IP Aliases mappings in batch
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)
        for r in records:
            src_ip = r.get("src")
            dst_ip = r.get("dst")
            r["src_domain"] = alias_map.get(src_ip) or dns_map.get(src_ip, "")
            r["dst_domain"] = alias_map.get(dst_ip) or dns_map.get(dst_ip, "")
            r["sport_name"] = port_aliases_cache.get(r.get("sport"), "") if r.get("sport") is not None else ""
            r["dport_name"] = port_aliases_cache.get(r.get("dport"), "") if r.get("dport") is not None else ""
            rule_ip = r.get("rule_ip")
            r["rule_ip_alias"] = resolve_ip_alias(rule_ip) if rule_ip else ""
            if r.get("protocol") is not None:
                r["proto_name"] = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})")
            else:
                r["proto_name"] = "N/A"
            
        return {
            "total": total_records,
            "limit": limit,
            "offset": offset,
            "records": records
        }
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/matches")
def clear_audit_matches():
    try:
        client = get_ch_client()
        client.command("TRUNCATE TABLE matched_flows")
        return {"status": "success", "message": "Permanently matched records cleared."}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/matches/{match_id}")
def delete_single_audit_match(match_id: str):
    try:
        client = get_ch_client()
        client.command("ALTER TABLE matched_flows DELETE WHERE id = %(id)s", parameters={"id": match_id})
        return {"status": "success", "message": f"Match record {match_id} deleted."}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches/export")
def export_audit_matches(
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    flag: Optional[str] = Query(None)
):
    import io
    import csv
    from fastapi.responses import StreamingResponse
    
    try:
        client = get_ch_client()
        where_clauses = []
        params = {}
        
        if src:
            where_clauses.append(build_ip_where_clause("src", src, params, "src"))
        if dst:
            where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
        if sport is not None:
            where_clauses.append("sport = %(sport)s")
            params["sport"] = sport
        if dport is not None:
            where_clauses.append("dport = %(dport)s")
            params["dport"] = dport
        if port is not None:
            where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
            params["port"] = port
        if flag:
            where_clauses.append("match_flag = %(flag)s")
            params["flag"] = flag.strip().lower()
            
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        query = f"""
            SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, ts, rule_ip, rule_port, match_flag, match_ts
            FROM matched_flows
            {where_sql}
            ORDER BY match_ts DESC, ts DESC
            LIMIT 100000
        """
        
        data_result = client.query(query, parameters=params)
        column_names = data_result.column_names
        
        # Collect unique IPs to resolve domains from DNS cache
        ips_to_resolve = set()
        for row in data_result.result_rows:
            r = dict(zip(column_names, row))
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
        dns_map = get_dns_mappings(ips_to_resolve)
        
        # CSV generator
        def csv_generator():
            yield "\ufeff"
            output = io.StringIO()
            writer = csv.writer(output)
            
            # CSV Headers
            headers = [
                "Audit Time", "Flow Time", "Flag", "Matched IP Rule", "Matched Port Rule",
                "Source IP", "Source Domain", "Source Port", "Source Port Name",
                "Destination IP", "Destination Domain", "Destination Port", "Destination Port Name",
                "Protocol", "Packets", "Bytes"
            ]
            writer.writerow(headers)
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            
            for row_vals in data_result.result_rows:
                r = dict(zip(column_names, row_vals))
                
                # Format dates
                m_ts = r["match_ts"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(r["match_ts"], datetime) else str(r["match_ts"])
                f_ts = r["ts"].strftime("%Y-%m-%d %H:%M:%S") if isinstance(r["ts"], datetime) else str(r["ts"])
                
                # Flag translation
                flag_val = "關注" if r["match_flag"] == "watch" else "異常"
                
                # DNS and Aliases resolution
                src_ip = r["src"]
                dst_ip = r["dst"]
                src_domain = resolve_ip_alias(src_ip) or dns_map.get(src_ip, "")
                dst_domain = resolve_ip_alias(dst_ip) or dns_map.get(dst_ip, "")
                
                sport_val = r["sport"]
                dport_val = r["dport"]
                sport_name = port_aliases_cache.get(sport_val, "")
                dport_name = port_aliases_cache.get(dport_val, "")
                
                p_name = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})" if r["protocol"] is not None else "N/A")
                rule_ip_val = f"{r['rule_ip']} ({resolve_ip_alias(r['rule_ip'])})" if r['rule_ip'] and resolve_ip_alias(r['rule_ip']) else (r['rule_ip'] or "(任意)")
                row_data = [
                    m_ts, f_ts, flag_val, rule_ip_val, r["rule_port"] or "(任意)",
                    src_ip, src_domain, sport_val, sport_name,
                    dst_ip, dst_domain, dport_val, dport_name,
                    p_name, r["packets"], r["octets"]
                ]
                writer.writerow(row_data)
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
                
        headers = {
            'Content-Disposition': 'attachment; filename="anomalous_traffic_report.csv"',
            'Content-Type': 'text/csv; charset=utf-8'
        }
        return StreamingResponse(csv_generator(), headers=headers)
        
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))


# Serve Static files. Ensure static directory exists
os.makedirs("static", exist_ok=True)

# Mount files inside static/ directory
app.mount("/", StaticFiles(directory="static", html=True), name="static")

@app.exception_handler(404)
def not_found_handler(request, exc):
    # Fallback to index.html for SPA routing
    index_path = os.path.join("static", "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return JSONResponse(status_code=404, content={"message": "Not Found"})
