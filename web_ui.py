import os
import sys
import sqlite3
import json
import socket
import threading
import clickhouse_connect
import ipaddress
import time
import hashlib
import secrets
from collections import OrderedDict
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from concurrent.futures import ThreadPoolExecutor
from typing import Optional, List, Dict, Any, Iterable, Tuple
from fastapi import FastAPI, Query, HTTPException, Request, Response, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

# Standard Taiwan Timezone (UTC+8)
TW_TZ = ZoneInfo("Asia/Taipei")

def now_tw() -> datetime:
    """Return current timezone-aware datetime in Asia/Taipei."""
    return datetime.now(TW_TZ)

def now_tw_str() -> str:
    """Return current datetime string in Asia/Taipei formatted as YYYY-MM-DD HH:MM:SS."""
    return now_tw().strftime("%Y-%m-%d %H:%M:%S")

def parse_tw_datetime(dt_str: str) -> datetime:
    """Parse datetime string and ensure it is timezone-aware in Asia/Taipei."""
    if not dt_str:
        return now_tw()
    clean_str = str(dt_str).strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(clean_str, fmt)
            return dt.replace(tzinfo=TW_TZ)
        except ValueError:
            continue
    try:
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=TW_TZ)
        return dt.astimezone(TW_TZ)
    except Exception:
        return now_tw()

app = FastAPI(title="Netflow Collector Web UI")

DB_PATH = os.getenv("SQLITE_DB_PATH", "flows.db")

# ---------------- Authentication Utilities ----------------
session_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}
session_cache_lock = threading.Lock()
SESSION_CACHE_TTL = 60.0  # 60 seconds in-memory cache

def invalidate_session_cache(token: Optional[str] = None, user_id: Optional[int] = None):
    with session_cache_lock:
        if token is not None:
            session_cache.pop(token, None)
        elif user_id is not None:
            to_remove = [t for t, (_, u) in session_cache.items() if u.get("id") == user_id]
            for t in to_remove:
                session_cache.pop(t, None)
        else:
            session_cache.clear()

def hash_password(password: str, salt: str) -> str:
    """Hash password using PBKDF2 HMAC SHA-256."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000).hex()

def verify_session_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify session token from cache or SQLite. Returns user dict if valid and unexpired."""
    if not token:
        return None
    now_mono = time.monotonic()
    with session_cache_lock:
        cached = session_cache.get(token)
        if cached and (now_mono - cached[0]) < SESSION_CACHE_TTL:
            return cached[1]

    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cur = conn.cursor()
        cur.execute("""
            SELECT s.token, s.user_id, s.username, s.role, s.expires_at, u.is_active, u.must_change_password
            FROM user_sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.token = ?
        """, (token,))
        row = cur.fetchone()
        conn.close()
        if not row:
            invalidate_session_cache(token=token)
            return None
        
        token_str, user_id, username, role, expires_at_str, is_active, must_change_password = row
        if not is_active:
            invalidate_session_cache(token=token)
            return None
            
        expires_at = parse_tw_datetime(expires_at_str)
        if now_tw() > expires_at:
            delete_session(token)
            return None
            
        user_dict = {
            "id": user_id,
            "username": username,
            "role": role,
            "must_change_password": bool(must_change_password)
        }
        with session_cache_lock:
            if len(session_cache) > 1000:
                session_cache.clear()
            session_cache[token] = (now_mono, user_dict)
        return user_dict
    except Exception as e:
        print(f"[Auth] Error verifying session token: {e}")
        return None

def delete_session(token: str):
    """Delete a session token from SQLite."""
    invalidate_session_cache(token=token)
    try:
        conn = sqlite3.connect(DB_PATH, timeout=30.0)
        cur = conn.cursor()
        cur.execute("DELETE FROM user_sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_current_user_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """Extract and verify session user from request cookie or Authorization header."""
    token = request.cookies.get("session_token")
    if not token:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header[7:].strip()
    return verify_session_token(token) if token else None

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
            "INSERT OR REPLACE INTO dns_cache (ip, domain, last_resolved) VALUES (?, ?, ?)",
            (ip, hostname, now_tw_str())
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
    now = now_tw()
    
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
                    last_resolved = parse_tw_datetime(last_resolved_str)
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
resolved_cidr_cache: OrderedDict[str, Optional[str]] = OrderedDict()
resolved_cidr_lock = threading.Lock()
MAX_RESOLVED_CIDR_CACHE = 50000
ip_aliases_total_count_cache: Optional[int] = None

def _cache_resolved_ip(ip_str: str, alias: Optional[str]):
    with resolved_cidr_lock:
        resolved_cidr_cache[ip_str] = alias
        resolved_cidr_cache.move_to_end(ip_str)
        if len(resolved_cidr_cache) > MAX_RESOLVED_CIDR_CACHE:
            resolved_cidr_cache.popitem(last=False)

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
    global ip_aliases_cache, ip_aliases_total_count_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        # Only load exact IP matches into memory cache to save memory
        cur.execute("SELECT ip, name FROM ip_aliases WHERE ip NOT LIKE '%/%'")
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM ip_aliases")
        ip_aliases_total_count_cache = cur.fetchone()[0]
        conn.close()
        
        ip_aliases_cache = {row[0].strip(): row[1].strip() for row in rows}
        with resolved_cidr_lock:
            resolved_cidr_cache.clear()
        print(f"[Startup Init] Loaded {len(ip_aliases_cache)} exact IP aliases into cache (total rows: {ip_aliases_total_count_cache}).")
    except Exception as e:
        print(f"[Startup Init] Error loading IP aliases into cache: {e}")

def find_ips_by_alias(alias_query: str, max_results: int = 100) -> List[str]:
    """Search SQLite ip_aliases by alias name (exact match or substring match) and return list of IP/CIDR strings."""
    if not alias_query or not str(alias_query).strip():
        return []
    alias_clean = str(alias_query).strip()
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute(
            "SELECT ip FROM ip_aliases WHERE name = ? OR name LIKE ? LIMIT ?",
            (alias_clean, f"%{alias_clean}%", max_results)
        )
        rows = cur.fetchall()
        conn.close()
        return [r[0].strip() for r in rows if r[0]]
    except Exception as e:
        print(f"[find_ips_by_alias] Error: {e}", file=sys.stderr)
        return []

def build_alias_where_clause(col: str, alias_query: str, params: dict, prefix: str) -> str:
    """Build ClickHouse SQL clause that matches records where `col` has an IP belonging to `alias_query`."""
    matched_ips = find_ips_by_alias(alias_query)
    if not matched_ips:
        return "1 = 0"
    
    sub_clauses = []
    for idx, ip_val in enumerate(matched_ips):
        param_k = f"{prefix}_al_{idx}"
        if col in ("any", "any_ip", "ip_alias", "alias"):
            c_src = build_ip_where_clause("src", ip_val, params, f"{param_k}_s")
            c_dst = build_ip_where_clause("dst", ip_val, params, f"{param_k}_d")
            sub_clauses.append(f"({c_src} OR {c_dst})")
        else:
            sub_clauses.append(build_ip_where_clause(col, ip_val, params, param_k))
            
    if len(sub_clauses) == 1:
        return sub_clauses[0]
    return f"({' OR '.join(sub_clauses)})"

def build_ip_where_clause(col: str, ip_query: str, params: dict, param_key: str) -> str:
    val = ip_query.strip().lower()
    safe_col = f"if(isIPv4String({col}) OR isIPv6String({col}), {col}, '0.0.0.0')"
    if val == "internal":
        return (
            f"((isIPv4String({col}) OR isIPv6String({col})) AND "
            f"(isIPAddressInRange({safe_col}, '192.168.0.0/16') OR "
            f"isIPAddressInRange({safe_col}, '172.16.0.0/12') OR "
            f"isIPAddressInRange({safe_col}, '10.0.0.0/8')))"
        )
    elif val == "external":
        return (
            f"((isIPv4String({col}) OR isIPv6String({col})) AND NOT "
            f"(isIPAddressInRange({safe_col}, '192.168.0.0/16') OR "
            f"isIPAddressInRange({safe_col}, '172.16.0.0/12') OR "
            f"isIPAddressInRange({safe_col}, '10.0.0.0/8')))"
        )
    else:
        if "/" in ip_query:
            params[param_key] = ip_query.strip()
            return f"((isIPv4String({col}) OR isIPv6String({col})) AND isIPAddressInRange({safe_col}, %({param_key})s))"
        else:
            raw_str = ip_query.strip()
            # If string contains characters not typical in pure IP prefixes, check alias
            is_ip_like = True
            for ch in raw_str:
                if ch not in "0123456789abcdefABCDEF.:/%":
                    is_ip_like = False
                    break
            if not is_ip_like:
                matched_ips = find_ips_by_alias(raw_str)
                if matched_ips:
                    sub_c = []
                    for idx, mip in enumerate(matched_ips):
                        sub_c.append(build_ip_where_clause(col, mip, params, f"{param_key}_al_{idx}"))
                    return f"({' OR '.join(sub_c)})" if len(sub_c) > 1 else sub_c[0]

            params[param_key] = f"{raw_str}%"
            return f"{col} LIKE %({param_key})s"

def parse_conditions_where_clause(conditions_json: Optional[str], logic: str, params: dict, prefix: str = "dyn") -> Optional[str]:
    """Parse dynamic multi-condition JSON and return combined ClickHouse SQL clause."""
    if not conditions_json or conditions_json == "[]":
        return None
    try:
        import json
        cond_list = json.loads(conditions_json)
        if not isinstance(cond_list, list) or not cond_list:
            return None
        
        clauses = []
        for idx, item in enumerate(cond_list):
            if not isinstance(item, dict):
                continue
            field = str(item.get("field", "")).strip().lower()
            val = str(item.get("val", "")).strip()
            if not val:
                continue

            sub_key = f"{prefix}_{idx}"
            if field in ("src", "src_ip"):
                clauses.append(build_ip_where_clause("src", val, params, f"{sub_key}_src"))
            elif field in ("dst", "dst_ip"):
                clauses.append(build_ip_where_clause("dst", val, params, f"{sub_key}_dst"))
            elif field in ("ip", "any_ip"):
                c_src = build_ip_where_clause("src", val, params, f"{sub_key}_asrc")
                c_dst = build_ip_where_clause("dst", val, params, f"{sub_key}_adst")
                clauses.append(f"({c_src} OR {c_dst})")
            elif field in ("alias", "ip_alias", "any_alias"):
                clauses.append(build_alias_where_clause("any", val, params, f"{sub_key}_alias"))
            elif field in ("src_alias", "source_alias"):
                clauses.append(build_alias_where_clause("src", val, params, f"{sub_key}_salias"))
            elif field in ("dst_alias", "dest_alias"):
                clauses.append(build_alias_where_clause("dst", val, params, f"{sub_key}_dalias"))
            elif field in ("sport", "src_port"):
                try:
                    params[f"{sub_key}_sport"] = int(val)
                    clauses.append(f"sport = %({sub_key}_sport)s")
                except ValueError:
                    pass
            elif field in ("dport", "dst_port"):
                try:
                    params[f"{sub_key}_dport"] = int(val)
                    clauses.append(f"dport = %({sub_key}_dport)s")
                except ValueError:
                    pass
            elif field in ("port", "any_port"):
                try:
                    params[f"{sub_key}_aport"] = int(val)
                    clauses.append(f"(sport = %({sub_key}_aport)s OR dport = %({sub_key}_aport)s)")
                except ValueError:
                    pass
            elif field in ("proto", "protocol"):
                p_num = None
                for num, name in PROTO_NAME_MAP.items():
                    if name.upper() == val.upper():
                        p_num = num
                        break
                if p_num is not None:
                    params[f"{sub_key}_pnum"] = p_num
                    params[f"{sub_key}_pstr"] = val
                    clauses.append(f"(proto ILIKE %({sub_key}_pstr)s OR protocol = %({sub_key}_pnum)s)")
                elif val.isdigit():
                    params[f"{sub_key}_pnum"] = int(val)
                    params[f"{sub_key}_pstr"] = val
                    clauses.append(f"(proto ILIKE %({sub_key}_pstr)s OR protocol = %({sub_key}_pnum)s)")
                else:
                    params[f"{sub_key}_pstr"] = val
                    clauses.append(f"proto ILIKE %({sub_key}_pstr)s")

        if not clauses:
            return None

        join_logic = " OR " if str(logic).strip().upper() == "OR" else " AND "
        return f"({join_logic.join(clauses)})"
    except Exception as e:
        print(f"[parse_conditions_where_clause] Error: {e}", file=sys.stderr)
        return None

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

    with resolved_cidr_lock:
        if ip_str in resolved_cidr_cache:
            resolved_cidr_cache.move_to_end(ip_str)
            return resolved_cidr_cache[ip_str]
        
    # 2. Fast O(log N) reverse B-Tree CIDR range match from SQLite
    try:
        if "/" in ip_str:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT name FROM ip_aliases WHERE ip = ? LIMIT 1", (ip_str,))
            row = cur.fetchone()
            conn.close()
            alias = row[0] if row else None
            _cache_resolved_ip(ip_str, alias)
            return alias

        ip_obj = ipaddress.ip_address(ip_str)
        ip_hex = ip_to_hex(ip_obj)
        min_hex = "v4-00000000" if ip_obj.version == 4 else "v6-00000000000000000000000000000000"
        
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
            SELECT name FROM (
                SELECT name, end_ip, prefix_len FROM ip_aliases
                WHERE start_ip <= ? AND start_ip >= ?
                ORDER BY start_ip DESC LIMIT 16
            )
            WHERE end_ip >= ?
            ORDER BY prefix_len DESC LIMIT 1
        """, (ip_hex, min_hex, ip_hex))
        row = cur.fetchone()
        conn.close()
        
        alias = row[0] if row else None
        _cache_resolved_ip(ip_str, alias)
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
        ip_lower = ip_clean.lower()
        if ip_lower == "internal":
            results[ip_clean] = "Private IP"
            continue
        elif ip_lower == "external":
            results[ip_clean] = "Public IP"
            continue

        if ip_clean in ip_aliases_cache:
            results[ip_clean] = ip_aliases_cache[ip_clean]
            continue

        with resolved_cidr_lock:
            if ip_clean in resolved_cidr_cache:
                resolved_cidr_cache.move_to_end(ip_clean)
                val = resolved_cidr_cache[ip_clean]
                if val:
                    results[ip_clean] = val
                continue

        missing_ips.append(ip_clean)
            
    if not missing_ips:
        return results
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        for ip in set(missing_ips):
            try:
                if "/" in ip:
                    cur.execute("SELECT name FROM ip_aliases WHERE ip = ? LIMIT 1", (ip,))
                    row = cur.fetchone()
                    alias = row[0] if row else None
                    _cache_resolved_ip(ip, alias)
                    if alias:
                        results[ip] = alias
                    continue

                ip_obj = ipaddress.ip_address(ip)
                ip_hex = ip_to_hex(ip_obj)
                min_hex = "v4-00000000" if ip_obj.version == 4 else "v6-00000000000000000000000000000000"
                
                cur.execute("""
                    SELECT name FROM (
                        SELECT name, end_ip, prefix_len FROM ip_aliases
                        WHERE start_ip <= ? AND start_ip >= ?
                        ORDER BY start_ip DESC LIMIT 16
                    )
                    WHERE end_ip >= ?
                    ORDER BY prefix_len DESC LIMIT 1
                """, (ip_hex, min_hex, ip_hex))
                row = cur.fetchone()
                alias = row[0] if row else None
                _cache_resolved_ip(ip, alias)
                if alias:
                    results[ip] = alias
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
        cur.execute("CREATE INDEX IF NOT EXISTS idx_ip_aliases_name ON ip_aliases (name)")
        
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

        # Initialize system settings table
        cur.execute("""CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT,
            updated_at DATETIME
        )""")
        
        tw_now = now_tw_str()
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('netflow_port', '2055', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('ipfix_port', '4739', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_days', '7', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_schedule_time', '03:00', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_enabled', '1', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_last_run', '', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_next_run', '', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_last_status', 'never', ?)", (tw_now,))
        cur.execute("INSERT OR IGNORE INTO system_settings (key, value, updated_at) VALUES ('retention_last_message', '排程尚未執行', ?)", (tw_now,))

        # Initialize users table
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            role TEXT DEFAULT 'admin',
            is_active INTEGER DEFAULT 1,
            must_change_password INTEGER DEFAULT 0,
            created_at DATETIME,
            last_login DATETIME
        )""")
        
        # Initialize user sessions table
        cur.execute("""CREATE TABLE IF NOT EXISTS user_sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            role TEXT NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )""")
        
        # Initialize collector allowed CIDRs table
        cur.execute("""CREATE TABLE IF NOT EXISTS collector_allowed_cidrs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cidr TEXT NOT NULL UNIQUE,
            description TEXT,
            created_at DATETIME
        )""")
        
        # Pre-populate default admin user if none exists
        cur.execute("SELECT COUNT(*) FROM users")
        if cur.fetchone()[0] == 0:
            salt = secrets.token_hex(16)
            pwd_hash = hash_password("admin123", salt)
            cur.execute("""
                INSERT INTO users (username, password_hash, salt, role, is_active, must_change_password, created_at)
                VALUES ('admin', ?, ?, 'admin', 1, 1, ?)
            """, (pwd_hash, salt, tw_now))
            print("[Startup Init] Default admin user initialized (admin / admin123, must_change_password=1).")
        
        conn.commit()
        conn.close()
        print("[Startup Init] SQLite tables (users, sessions, allowed CIDRs, system settings) initialized successfully.")
        
        load_port_aliases()
        load_ip_aliases()
    except Exception as e:
        print(f"[Startup Init] Error initializing SQLite tables: {e}")

    # Initialize ClickHouse tables if they do not exist
    init_clickhouse_tables()

def ensure_matched_flows_table(client=None):
    """Ensure the matched_flows table exists in ClickHouse."""
    try:
        if client is None:
            client = get_ch_client()
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
    except Exception as e:
        print(f"[Ensure Matched Flows Table] Warning: {e}")

def init_clickhouse_tables(client=None):
    """Initialize ClickHouse tables if they do not exist."""
    try:
        if client is None:
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
        
        retention_days = int(get_system_setting("retention_days", "7"))
        client.command(f"""
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
        
        client.command(f"""
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
        
        # Initialize matched_flows table (without TTL)
        ensure_matched_flows_table(client)
        
        # Ensure TTL is applied to existing tables if they were created without it
        try:
            client.command(f"ALTER TABLE ipfix MODIFY TTL ts + INTERVAL {retention_days} DAY")
            client.command(f"ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL {retention_days} DAY")
        except Exception as alter_err:
            print(f"[Startup Init] Warning altering ClickHouse TTL: {alter_err}")
            
        print(f"[Startup Init] ClickHouse database tables initialized successfully ({retention_days}-day TTL).")
    except Exception as e:
        print(f"[Startup Init] Error initializing ClickHouse tables: {e}")

def get_system_setting(key: str, default_val: str) -> str:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT value FROM system_settings WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        return row[0] if row and row[0] is not None else default_val
    except Exception:
        return default_val

def set_system_setting(key: str, value: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO system_settings (key, value, updated_at) 
        VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at
    """, (key, value, now_tw_str()))
    conn.commit()
    conn.close()

# ---------------- Retention Policy & Scheduler Logic ----------------
def calculate_next_retention_run(schedule_time_str: str, last_run_str: str = "") -> datetime:
    """Calculate the next scheduled run datetime in TW_TZ."""
    now = now_tw()
    try:
        parts = schedule_time_str.split(":")
        hour, minute = int(parts[0]), int(parts[1])
    except Exception:
        hour, minute = 3, 0
    
    target_today = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    
    if now < target_today:
        return target_today
    else:
        # Check if already ran today
        if last_run_str:
            try:
                last_dt = parse_tw_datetime(last_run_str)
                if last_dt >= target_today:
                    return target_today + timedelta(days=1)
            except Exception:
                pass
        # Missed today's run or not yet run -> trigger now
        return now

def run_retention_cleanup() -> Dict[str, Any]:
    """Execute retention policy deletion in ClickHouse and update SQLite status."""
    try:
        days = int(get_system_setting("retention_days", "7"))
        current_tw = now_tw()
        cutoff_dt = current_tw - timedelta(days=days)
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        client = get_ch_client()
        client.command("ALTER TABLE ipfix DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        client.command("ALTER TABLE netflow9 DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        
        # Dynamically align ClickHouse table TTL
        try:
            client.command(f"ALTER TABLE ipfix MODIFY TTL ts + INTERVAL {days} DAY")
            client.command(f"ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL {days} DAY")
        except Exception as ttl_err:
            print(f"[Retention] Warning updating ClickHouse TTL: {ttl_err}")
            
        run_ts_str = current_tw.strftime("%Y-%m-%d %H:%M:%S")
        set_system_setting("retention_last_run", run_ts_str)
        set_system_setting("retention_last_status", "success")
        msg = f"排程清理成功完成：已清除 {cutoff_str} 以前（保留 {days} 天）之流量資料。"
        set_system_setting("retention_last_message", msg)
        print(f"[Retention] {msg}", flush=True)
        return {"status": "success", "message": msg, "cutoff": cutoff_str, "last_run": run_ts_str}
    except Exception as e:
        err_msg = f"排程清理失敗: {e}"
        set_system_setting("retention_last_status", "failed")
        set_system_setting("retention_last_message", err_msg)
        print(f"[Retention] {err_msg}", flush=True)
        return {"status": "failed", "message": err_msg}

def retention_scheduler_loop():
    """Background thread checking retention schedule periodically in Asia/Taipei timezone."""
    print("[Retention] Background retention scheduler thread started.", flush=True)
    try:
        time.sleep(10)
    except Exception:
        pass
    while True:
        try:
            enabled = get_system_setting("retention_enabled", "1") == "1"
            if enabled:
                schedule_time = get_system_setting("retention_schedule_time", "03:00")
                last_run_str = get_system_setting("retention_last_run", "")
                next_run_str = get_system_setting("retention_next_run", "")
                
                if not next_run_str:
                    next_dt = calculate_next_retention_run(schedule_time, last_run_str)
                    next_run_str = next_dt.strftime("%Y-%m-%d %H:%M:%S")
                    set_system_setting("retention_next_run", next_run_str)
                
                next_run_dt = parse_tw_datetime(next_run_str)
                current_tw = now_tw()
                
                # Check if current time is greater than or equal to next scheduled run time
                if current_tw >= next_run_dt:
                    print(f"[Retention] Current TW time ({current_tw.strftime('%Y-%m-%d %H:%M:%S')}) >= Next run ({next_run_str}). Executing scheduled cleanup...", flush=True)
                    run_retention_cleanup()
                    
                    # Schedule next run for tomorrow at specified schedule_time
                    try:
                        parts = schedule_time.split(":")
                        h, m = int(parts[0]), int(parts[1])
                    except Exception:
                        h, m = 3, 0
                    next_target = current_tw.replace(hour=h, minute=m, second=0, microsecond=0) + timedelta(days=1)
                    set_system_setting("retention_next_run", next_target.strftime("%Y-%m-%d %H:%M:%S"))
        except Exception as e:
            print(f"[Retention] Scheduler error: {e}", flush=True)
            
        time.sleep(30)

@app.on_event("startup")
def on_startup():
    init_db()
    # Start background daily traffic audit scheduler
    t1 = threading.Thread(target=audit_scheduler_loop, daemon=True)
    t1.start()
    # Start background retention cleanup scheduler
    t2 = threading.Thread(target=retention_scheduler_loop, daemon=True)
    t2.start()

# ---------------- Request Models ----------------
class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: str = "user"  # "admin" or "user"

class UpdateUserRequest(BaseModel):
    role: Optional[str] = None
    is_active: Optional[bool] = None

class ResetUserPasswordRequest(BaseModel):
    new_password: str

class AllowedCidrRequest(BaseModel):
    cidr: str
    description: Optional[str] = ""

class RetentionSettingsRequest(BaseModel):
    retention_days: int = Field(..., ge=1, le=3650)
    schedule_time: str = Field(..., pattern=r"^\d{2}:\d{2}$")
    enabled: bool = True

# ---------------- Authentication Middleware ----------------
@app.middleware("http")
async def auth_middleware(request: Request, call_next):
    path = request.url.path
    # Public routes: static assets, root page, login & me check
    if (
        path in ("/", "/favicon.ico")
        or path.startswith("/static/")
        or path in ("/api/auth/login", "/api/auth/me")
    ):
        return await call_next(request)
    
    # Any other /api/* route requires authentication
    if path.startswith("/api/"):
        user = get_current_user_from_request(request)
        if not user:
            return JSONResponse(status_code=401, content={"detail": "未授權或連線逾期，請先登入系統。"})
        request.state.user = user

    return await call_next(request)

# ---------------- Auth API Endpoints ----------------
@app.get("/api/auth/me")
def auth_me(request: Request):
    """Check current login status and user profile."""
    user = get_current_user_from_request(request)
    if not user:
        return {"authenticated": False}
    return {
        "authenticated": True,
        "user": user
    }

@app.post("/api/auth/login")
def auth_login(payload: LoginRequest, response: Response):
    """Log in user and issue session token."""
    username = payload.username.strip()
    password = payload.password
    
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, salt, role, is_active, must_change_password FROM users WHERE username = ?", (username,))
    user_row = cur.fetchone()
    
    if not user_row:
        conn.close()
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤。")
        
    if not user_row["is_active"]:
        conn.close()
        raise HTTPException(status_code=401, detail="此帳號已停用，請聯繫系統管理員。")
        
    computed_hash = hash_password(password, user_row["salt"])
    if computed_hash != user_row["password_hash"]:
        conn.close()
        raise HTTPException(status_code=401, detail="帳號或密碼錯誤。")
        
    # Generate session token (7-day validity)
    token = secrets.token_hex(32)
    now_dt = now_tw()
    expires_dt = now_dt + timedelta(days=7)
    now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")
    expires_str = expires_dt.strftime("%Y-%m-%d %H:%M:%S")
    
    cur.execute("""
        INSERT INTO user_sessions (token, user_id, username, role, expires_at, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (token, user_row["id"], user_row["username"], user_row["role"], expires_str, now_str))
    
    cur.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user_row["id"]))
    conn.commit()
    conn.close()
    
    response.set_cookie(
        key="session_token",
        value=token,
        max_age=7 * 86400,
        httponly=True,
        samesite="lax",
        secure=False
    )
    
    return {
        "status": "success",
        "token": token,
        "user": {
            "id": user_row["id"],
            "username": user_row["username"],
            "role": user_row["role"],
            "must_change_password": bool(user_row["must_change_password"])
        }
    }

@app.post("/api/auth/logout")
def auth_logout(request: Request, response: Response):
    """Log out current user and invalidate session."""
    token = request.cookies.get("session_token")
    if token:
        delete_session(token)
    response.delete_cookie("session_token")
    return {"status": "success", "message": "已成功登出。"}

@app.post("/api/auth/change-password")
def auth_change_password(payload: ChangePasswordRequest, request: Request):
    """Change current logged-in user password."""
    user = getattr(request.state, "user", None) or get_current_user_from_request(request)
    if not user:
        raise HTTPException(status_code=401, detail="請先登入。")
        
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密碼長度至少需為 6 個字元。")
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, password_hash, salt FROM users WHERE id = ?", (user["id"],))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到使用者資料。")
        
    if hash_password(payload.old_password, row["salt"]) != row["password_hash"]:
        conn.close()
        raise HTTPException(status_code=400, detail="目前舊密碼輸入不正確。")
        
    new_salt = secrets.token_hex(16)
    new_hash = hash_password(payload.new_password, new_salt)
    cur.execute("""
        UPDATE users 
        SET password_hash = ?, salt = ?, must_change_password = 0 
        WHERE id = ?
    """, (new_hash, new_salt, user["id"]))
    conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user["id"])
    
    return {"status": "success", "message": "密碼已成功修改！"}

# ---------------- User Management API (Admin Only) ----------------
def verify_admin_request(request: Request):
    user = getattr(request.state, "user", None) or get_current_user_from_request(request)
    if not user or user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="權限不足，僅系統管理員可執行此管理操作。")
    return user

@app.get("/api/users")
def get_users(request: Request):
    verify_admin_request(request)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("""
        SELECT id, username, role, is_active, must_change_password, created_at, last_login 
        FROM users 
        ORDER BY id ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows

@app.post("/api/users")
def create_user(payload: CreateUserRequest, request: Request):
    verify_admin_request(request)
    uname = payload.username.strip()
    if not uname or len(uname) < 3:
        raise HTTPException(status_code=400, detail="帳號名稱長度至少需為 3 個字元。")
    if len(payload.password) < 6:
        raise HTTPException(status_code=400, detail="密碼長度至少需為 6 個字元。")
    role = "admin" if payload.role == "admin" else "user"
    
    salt = secrets.token_hex(16)
    pwd_hash = hash_password(payload.password, salt)
    
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO users (username, password_hash, salt, role, is_active, must_change_password, created_at)
            VALUES (?, ?, ?, ?, 1, 0, ?)
        """, (uname, pwd_hash, salt, role, now_tw_str()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail=f"帳號 '{uname}' 已存在。")
    conn.close()
    return {"status": "success", "message": f"使用者 '{uname}' 已成功建立。"}

@app.put("/api/users/{user_id}")
def update_user(user_id: int, payload: UpdateUserRequest, request: Request):
    current_admin = verify_admin_request(request)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username, role, is_active FROM users WHERE id = ?", (user_id,))
    target_user = cur.fetchone()
    if not target_user:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到指定的使用者。")
        
    if target_user["username"] == "admin" and payload.is_active is False:
        conn.close()
        raise HTTPException(status_code=400, detail="不可停用預設 admin 管理員帳號。")
        
    updates = []
    params = []
    if payload.role in ("admin", "user"):
        updates.append("role = ?")
        params.append(payload.role)
    if payload.is_active is not None:
        updates.append("is_active = ?")
        params.append(1 if payload.is_active else 0)
        
    if updates:
        params.append(user_id)
        cur.execute(f"UPDATE users SET {', '.join(updates)} WHERE id = ?", params)
        conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user_id)
    return {"status": "success", "message": "使用者資料更新成功。"}

@app.post("/api/users/{user_id}/reset-password")
def reset_user_password(user_id: int, payload: ResetUserPasswordRequest, request: Request):
    verify_admin_request(request)
    if len(payload.new_password) < 6:
        raise HTTPException(status_code=400, detail="新密碼長度至少需為 6 個字元。")
        
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到指定的使用者。")
        
    new_salt = secrets.token_hex(16)
    new_hash = hash_password(payload.new_password, new_salt)
    cur.execute("UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0 WHERE id = ?", (new_hash, new_salt, user_id))
    cur.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user_id)
    return {"status": "success", "message": f"已重設使用者 '{user[1]}' 之密碼。"}

@app.delete("/api/users/{user_id}")
def delete_user(user_id: int, request: Request):
    current_admin = verify_admin_request(request)
    if current_admin["id"] == user_id:
        raise HTTPException(status_code=400, detail="不可刪除目前正在登入的管理員帳號。")
        
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
    user = cur.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="找不到指定的使用者。")
    if user["username"] == "admin":
        conn.close()
        raise HTTPException(status_code=400, detail="不可刪除系統預設之 admin 帳號。")
        
    cur.execute("DELETE FROM users WHERE id = ?", (user_id,))
    cur.execute("DELETE FROM user_sessions WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()
    invalidate_session_cache(user_id=user_id)
    return {"status": "success", "message": f"使用者 '{user['username']}' 已成功刪除。"}

# ---------------- Retention & Cleanup Settings API ----------------
@app.get("/api/settings/retention")
def get_retention_settings():
    """Retrieve data retention policy configuration and scheduled execution status."""
    try:
        retention_days = int(get_system_setting("retention_days", "7"))
        schedule_time = get_system_setting("retention_schedule_time", "03:00")
        enabled = get_system_setting("retention_enabled", "1") == "1"
        last_run = get_system_setting("retention_last_run", "")
        next_run = get_system_setting("retention_next_run", "")
        last_status = get_system_setting("retention_last_status", "never")
        last_message = get_system_setting("retention_last_message", "排程尚未執行")
        
        if not next_run:
            next_dt = calculate_next_retention_run(schedule_time, last_run)
            next_run = next_dt.strftime("%Y-%m-%d %H:%M:%S")
            set_system_setting("retention_next_run", next_run)
            
        return {
            "retention_days": retention_days,
            "schedule_time": schedule_time,
            "enabled": enabled,
            "last_run": last_run or "尚未執行",
            "next_run": next_run,
            "last_status": last_status,
            "last_message": last_message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"讀取資料保留設定失敗: {e}")

@app.post("/api/settings/retention")
def update_retention_settings(payload: RetentionSettingsRequest):
    """Update data retention days and scheduled execution time."""
    try:
        set_system_setting("retention_days", str(payload.retention_days))
        set_system_setting("retention_schedule_time", payload.schedule_time)
        set_system_setting("retention_enabled", "1" if payload.enabled else "0")
        
        # Calculate new next run
        last_run = get_system_setting("retention_last_run", "")
        next_dt = calculate_next_retention_run(payload.schedule_time, last_run)
        next_run_str = next_dt.strftime("%Y-%m-%d %H:%M:%S")
        set_system_setting("retention_next_run", next_run_str)
        
        # Update ClickHouse TTL dynamically
        client = get_ch_client()
        try:
            client.command(f"ALTER TABLE ipfix MODIFY TTL ts + INTERVAL {payload.retention_days} DAY")
            client.command(f"ALTER TABLE netflow9 MODIFY TTL ts + INTERVAL {payload.retention_days} DAY")
        except Exception as ttl_err:
            print(f"[Retention] Warning altering ClickHouse TTL: {ttl_err}")
            
        return {
            "status": "success",
            "message": f"資料保留政策已更新：保留 {payload.retention_days} 天，每日 {payload.schedule_time} 定時執行清理。",
            "retention_days": payload.retention_days,
            "schedule_time": payload.schedule_time,
            "enabled": payload.enabled,
            "next_run": next_run_str
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"更新資料保留設定失敗: {e}")

@app.post("/api/flows/cleanup/execute-retention")
def execute_retention_manual():
    """Manually trigger retention cleanup according to the configured retention days."""
    res = run_retention_cleanup()
    if res.get("status") == "failed":
        raise HTTPException(status_code=500, detail=res.get("message"))
    return res

# ---------------- Collector Allowed CIDRs API ----------------
@app.get("/api/settings/collector/cidrs")
def get_collector_cidrs():
    """Get list of allowed NetFlow / IPFIX exporter IP/CIDRs."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute("SELECT id, cidr, description, created_at FROM collector_allowed_cidrs ORDER BY id ASC")
        rows = [dict(r) for r in cur.fetchall()]
        conn.close()
        return rows
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"讀取收集器白名單失敗: {e}")

@app.post("/api/settings/collector/cidrs")
def add_collector_cidr(payload: AllowedCidrRequest):
    """Add a new CIDR or IP to the collector allowed whitelist."""
    raw_cidr = payload.cidr.strip()
    if not raw_cidr:
        raise HTTPException(status_code=400, detail="請輸入有效的 IP 或 CIDR 網段。")
    try:
        net = ipaddress.ip_network(raw_cidr, strict=False)
        normalized_cidr = str(net)
    except Exception:
        raise HTTPException(status_code=400, detail="無效的 CIDR 格式，例如 192.168.10.0/24 或 10.0.0.1")
        
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute("""
            INSERT INTO collector_allowed_cidrs (cidr, description, created_at)
            VALUES (?, ?, ?)
        """, (normalized_cidr, payload.description.strip(), now_tw_str()))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise HTTPException(status_code=400, detail=f"網段 '{normalized_cidr}' 已存在於白名單中。")
    conn.close()
    return {"status": "success", "message": f"已成功新增網段 '{normalized_cidr}' 至收集器允許白名單。"}

@app.delete("/api/settings/collector/cidrs/{cidr_id}")
def delete_collector_cidr(cidr_id: int):
    """Remove a CIDR from the collector allowed whitelist."""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM collector_allowed_cidrs WHERE id = ?", (cidr_id,))
    conn.commit()
    conn.close()
    return {"status": "success", "message": "已從收集器白名單移除該網段。"}

exporters_cache: Tuple[float, List[str]] = (0.0, [])
exporters_cache_lock = threading.Lock()
ch_query_executor = ThreadPoolExecutor(max_workers=8)

def _run_ch_query(sql: str, params: Optional[Dict[str, Any]] = None):
    client = get_ch_client()
    return client.query(sql, parameters=params or {})

@app.get("/api/exporters")
def get_exporters():
    """Get a list of all distinct exporter IPs from both tables (cached for 30s)."""
    global exporters_cache
    now_mono = time.monotonic()
    with exporters_cache_lock:
        if now_mono - exporters_cache[0] < 30.0 and exporters_cache[1]:
            return exporters_cache[1]
    try:
        client = get_ch_client()
        result = client.query("""
            SELECT DISTINCT exporter FROM (
                SELECT DISTINCT exporter FROM ipfix WHERE ts >= now() - INTERVAL 7 DAY
                UNION ALL
                SELECT DISTINCT exporter FROM netflow9 WHERE ts >= now() - INTERVAL 7 DAY
            ) WHERE exporter IS NOT NULL AND exporter != ''
        """)
        exporters = [row[0] for row in result.result_rows]
        if not exporters:
            result = client.query("""
                SELECT DISTINCT exporter FROM (
                    SELECT DISTINCT exporter FROM ipfix
                    UNION ALL
                    SELECT DISTINCT exporter FROM netflow9
                ) WHERE exporter IS NOT NULL AND exporter != ''
            """)
            exporters = [row[0] for row in result.result_rows]
        with exporters_cache_lock:
            exporters_cache = (now_mono, exporters)
        return exporters
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))
class CollectorSettingsRequest(BaseModel):
    netflow_port: int = Field(..., ge=1, le=65535, description="NetFlow v9 UDP listening port")
    ipfix_port: int = Field(..., ge=1, le=65535, description="IPFIX UDP listening port")

@app.get("/api/settings/collector")
def get_collector_settings():
    try:
        nf_port = int(get_system_setting("netflow_port", "2055"))
        ipfix_port = int(get_system_setting("ipfix_port", "4739"))
        return {
            "netflow_port": nf_port,
            "ipfix_port": ipfix_port
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to load collector settings: {e}")

@app.post("/api/settings/collector")
def update_collector_settings(payload: CollectorSettingsRequest):
    if payload.netflow_port == payload.ipfix_port:
        raise HTTPException(status_code=400, detail="NetFlow port and IPFIX port cannot be the same port.")
    
    try:
        set_system_setting("netflow_port", str(payload.netflow_port))
        set_system_setting("ipfix_port", str(payload.ipfix_port))
        
        return {
            "status": "success",
            "message": f"Collector listening ports updated successfully: NetFlow v9 (UDP {payload.netflow_port}), IPFIX (UDP {payload.ipfix_port}).",
            "netflow_port": payload.netflow_port,
            "ipfix_port": payload.ipfix_port
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to update collector settings: {e}")

@app.get("/api/flows")
def get_flows(
    table: str = Query("all", description="Table to search: 'all', 'ipfix', 'netflow9'"),
    ip: Optional[str] = Query(None, description="IP address or prefix (either source or destination)"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    alias: Optional[str] = Query(None, description="IP alias search (either source or destination)"),
    port: Optional[int] = Query(None, description="Port (either source or destination)"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
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

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "q_alias"))

        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "flow_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
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
    ip: Optional[str] = Query(None, description="IP address or prefix (either source or destination)"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    alias: Optional[str] = Query(None, description="IP alias search (either source or destination)"),
    port: Optional[int] = Query(None, description="Port (either source or destination)"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
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

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "exp_alias"))

        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "flow_exp_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
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

        # Collect unique IPs to resolve domains and aliases in batch
        ips_to_resolve = set()
        for row in result.result_rows:
            r = dict(zip(result.column_names, row))
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)

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
                    csv_row.append(alias_map.get(r["src"]) or dns_map.get(r["src"], ""))
                if "dst" in r:
                    csv_row.append(alias_map.get(r["dst"]) or dns_map.get(r["dst"], ""))
                
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

        filename = f"flow_export_{now_tw().strftime('%Y%m%d_%H%M%S')}.csv"
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
    ip: Optional[str] = Query(None, description="IP address or prefix (either source or destination)"),
    src: Optional[str] = Query(None, description="Source IP prefix"),
    dst: Optional[str] = Query(None, description="Destination IP prefix"),
    alias: Optional[str] = Query(None, description="IP alias search (either source or destination)"),
    port: Optional[int] = Query(None, description="Port (either source or destination)"),
    sport: Optional[int] = Query(None, description="Source port"),
    dport: Optional[int] = Query(None, description="Destination port"),
    proto: Optional[str] = Query(None, description="Protocol list, comma-separated"),
    exporter: Optional[str] = Query(None, description="Exporter IP"),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
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

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "s_alias"))

        if exporter:
            exp_parts = [e.strip() for e in exporter.split(",") if e.strip()]
            if exp_parts:
                where_clauses.append("exporter IN %(exporter_list)s")
                params["exporter_list"] = tuple(exp_parts)

        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "stats_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
            if src:
                where_clauses.append(build_ip_where_clause("src", src, params, "src"))
            if dst:
                where_clauses.append(build_ip_where_clause("dst", dst, params, "dst"))
            if port is not None:
                where_clauses.append("(sport = %(port)s OR dport = %(port)s)")
                params["port"] = port
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

        # Determine time bin grouping function before firing concurrent queries
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

        # Execute aggregation queries concurrently across ClickHouse thread-local clients
        q_totals = f"SELECT COUNT() as total_flows, SUM(packets) as total_packets, SUM(octets) as total_bytes FROM ({combined_flows})"
        q_top_src = f"SELECT src, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) GROUP BY src ORDER BY bytes DESC LIMIT 10"
        q_top_dst = f"SELECT dst, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) GROUP BY dst ORDER BY bytes DESC LIMIT 10"
        q_top_exp = f"SELECT exporter, SUM(octets) as bytes, COUNT() as flows FROM ({combined_flows}) GROUP BY exporter ORDER BY flows DESC LIMIT 5"
        q_protos = f"SELECT protocol, COUNT() as count, SUM(octets) as bytes FROM ({combined_flows}) GROUP BY protocol ORDER BY count DESC"
        q_time = f"SELECT {ch_group_fn} as time_bin, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) GROUP BY time_bin ORDER BY time_bin ASC"
        q_sport = f"SELECT sport, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) WHERE sport IS NOT NULL GROUP BY sport ORDER BY bytes DESC LIMIT 10"
        q_dport = f"SELECT dport, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows FROM ({combined_flows}) WHERE dport IS NOT NULL GROUP BY dport ORDER BY bytes DESC LIMIT 10"
        q_top_pairs = f"SELECT src, dst, SUM(octets) as bytes, COUNT() as flows FROM ({combined_flows}) GROUP BY src, dst ORDER BY bytes DESC LIMIT 1000"

        f_totals = ch_query_executor.submit(_run_ch_query, q_totals, params)
        f_top_src = ch_query_executor.submit(_run_ch_query, q_top_src, params)
        f_top_dst = ch_query_executor.submit(_run_ch_query, q_top_dst, params)
        f_top_exp = ch_query_executor.submit(_run_ch_query, q_top_exp, params)
        f_protos = ch_query_executor.submit(_run_ch_query, q_protos, params)
        f_time = ch_query_executor.submit(_run_ch_query, q_time, params)
        f_sport = ch_query_executor.submit(_run_ch_query, q_sport, params)
        f_dport = ch_query_executor.submit(_run_ch_query, q_dport, params)
        f_top_pairs = ch_query_executor.submit(_run_ch_query, q_top_pairs, params)

        # 1. Overall Totals
        res = f_totals.result()
        totals = dict(zip(res.column_names, res.result_rows[0]))
        total_flows = totals["total_flows"] or 0
        total_packets = totals["total_packets"] or 0
        total_bytes = totals["total_bytes"] or 0

        # 2. Top Sources by bytes
        res = f_top_src.result()
        top_sources = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 3. Top Destinations by bytes
        res = f_top_dst.result()
        top_destinations = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 4. Top Exporters
        res = f_top_exp.result()
        top_exporters = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 5. Protocols share
        res = f_protos.result()
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
        res = f_time.result()
        traffic_over_time = []
        for r_row in res.result_rows:
            r = dict(zip(res.column_names, r_row))
            tb = r["time_bin"]
            if isinstance(tb, datetime):
                r["time_bin"] = tb.strftime(time_format)
            traffic_over_time.append(r)

        # 7. Top Source Ports by bytes
        res = f_sport.result()
        top_source_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        # 8. Top Destination Ports by bytes
        res = f_dport.result()
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

        # 9. Top IP Aliases (Bidirectional aggregated, deduplicated if both endpoints share same alias)
        res_pairs = f_top_pairs.result()
        pair_rows = [dict(zip(res_pairs.column_names, r)) for r in res_pairs.result_rows]
        pair_ips = set()
        for r in pair_rows:
            if r.get("src"):
                pair_ips.add(r["src"])
            if r.get("dst"):
                pair_ips.add(r["dst"])
        alias_map_pairs = resolve_ip_aliases_batch(pair_ips)
        alias_aggregated = {}
        for r in pair_rows:
            s_alias = alias_map_pairs.get(r.get("src"))
            d_alias = alias_map_pairs.get(r.get("dst"))
            matched_aliases = set()
            if s_alias:
                matched_aliases.add(s_alias)
            if d_alias:
                matched_aliases.add(d_alias)
            for al in matched_aliases:
                if al not in alias_aggregated:
                    alias_aggregated[al] = {"name": al, "bytes": 0, "flows": 0}
                alias_aggregated[al]["bytes"] += (r.get("bytes") or 0)
                alias_aggregated[al]["flows"] += (r.get("flows") or 0)
        top_aliases = sorted(alias_aggregated.values(), key=lambda x: x["bytes"], reverse=True)[:10]

        return {
            "total_flows": total_flows,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "top_sources": top_sources,
            "top_destinations": top_destinations,
            "top_exporters": top_exporters,
            "protocols": protocols,
            "top_aliases": top_aliases,
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
        cutoff_dt = parse_tw_datetime(before)
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        client = get_ch_client()
        client.command("ALTER TABLE ipfix DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        client.command("ALTER TABLE netflow9 DELETE WHERE ts < %(cutoff)s", parameters={"cutoff": cutoff_str})
        
        now_str = now_tw_str()
        set_system_setting("retention_last_run", now_str)
        set_system_setting("retention_last_status", "success")
        msg = f"已成功佇列刪除在 {cutoff_str} (台灣時間) 之前的流量記錄。"
        set_system_setting("retention_last_message", f"手動清理：{msg}")
        
        return {"status": "success", "message": msg, "last_run": now_str}
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
    global ip_aliases_total_count_cache
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        
        where_clause = ""
        params = []
        if q and q.strip():
            q_clean = f"%{q.strip()}%"
            where_clause = "WHERE ip LIKE ? OR name LIKE ?"
            params = [q_clean, q_clean]
            cur.execute(f"SELECT COUNT(*) FROM ip_aliases {where_clause}", params)
            total_count = cur.fetchone()[0]
        else:
            if ip_aliases_total_count_cache is not None:
                total_count = ip_aliases_total_count_cache
            else:
                cur.execute("SELECT COUNT(*) FROM ip_aliases")
                total_count = cur.fetchone()[0]
                ip_aliases_total_count_cache = total_count
        
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

def is_internal_ip(ip_obj) -> bool:
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

def build_rule_sql_condition(rule: Dict[str, Any], idx: int, params: Dict[str, Any]) -> str:
    """
    Build a ClickHouse SQL boolean condition for a single audit rule.
    Supports:
      - IP: internal, external, CIDR (e.g. 192.168.1.0/24), single IP (e.g. 10.0.0.1)
      - Port: single port (e.g. 80), port range (e.g. 80-443)
    Rule matches if: (IP match) AND (Port match)
    """
    sub_conds = []
    
    # 1. IP condition
    ip_raw = rule.get("ip")
    if ip_raw:
        ip_str = str(ip_raw).strip()
        ip_lower = ip_str.lower()
        safe_src = "if(isIPv4String(src) OR isIPv6String(src), src, '0.0.0.0')"
        safe_dst = "if(isIPv4String(dst) OR isIPv6String(dst), dst, '0.0.0.0')"
        if ip_lower == "internal":
            internal_nets = f"isIPAddressInRange({safe_src}, '10.0.0.0/8') OR isIPAddressInRange({safe_src}, '172.16.0.0/12') OR isIPAddressInRange({safe_src}, '192.168.0.0/16')"
            internal_netd = f"isIPAddressInRange({safe_dst}, '10.0.0.0/8') OR isIPAddressInRange({safe_dst}, '172.16.0.0/12') OR isIPAddressInRange({safe_dst}, '192.168.0.0/16')"
            ip_cond = f"(((isIPv4String(src) OR isIPv6String(src)) AND ({internal_nets})) OR ((isIPv4String(dst) OR isIPv6String(dst)) AND ({internal_netd})))"
            sub_conds.append(ip_cond)
        elif ip_lower == "external":
            ext_nets = f"NOT (isIPAddressInRange({safe_src}, '10.0.0.0/8') OR isIPAddressInRange({safe_src}, '172.16.0.0/12') OR isIPAddressInRange({safe_src}, '192.168.0.0/16'))"
            ext_netd = f"NOT (isIPAddressInRange({safe_dst}, '10.0.0.0/8') OR isIPAddressInRange({safe_dst}, '172.16.0.0/12') OR isIPAddressInRange({safe_dst}, '192.168.0.0/16'))"
            ip_cond = f"(((isIPv4String(src) OR isIPv6String(src)) AND ({ext_nets})) OR ((isIPv4String(dst) OR isIPv6String(dst)) AND ({ext_netd})))"
            sub_conds.append(ip_cond)
        elif "/" in ip_str:
            p_name = f"rule_{idx}_cidr"
            params[p_name] = ip_str
            ip_cond = f"(((isIPv4String(src) OR isIPv6String(src)) AND isIPAddressInRange({safe_src}, %({p_name})s)) OR ((isIPv4String(dst) OR isIPv6String(dst)) AND isIPAddressInRange({safe_dst}, %({p_name})s)))"
            sub_conds.append(ip_cond)
        else:
            p_name = f"rule_{idx}_ip"
            params[p_name] = ip_str
            ip_cond = f"(src = %({p_name})s OR dst = %({p_name})s)"
            sub_conds.append(ip_cond)

    # 2. Port condition
    port_raw = rule.get("port")
    if port_raw is not None and str(port_raw).strip() != "":
        port_str = str(port_raw).strip()
        if "-" in port_str:
            parts = port_str.split("-")
            p_start_name = f"rule_{idx}_pstart"
            p_end_name = f"rule_{idx}_pend"
            params[p_start_name] = int(parts[0].strip())
            params[p_end_name] = int(parts[1].strip())
            port_cond = f"((sport >= %({p_start_name})s AND sport <= %({p_end_name})s) OR (dport >= %({p_start_name})s AND dport <= %({p_end_name})s))"
            sub_conds.append(port_cond)
        else:
            p_name = f"rule_{idx}_port"
            params[p_name] = int(port_str)
            port_cond = f"(sport = %({p_name})s OR dport = %({p_name})s)"
            sub_conds.append(port_cond)

    if not sub_conds:
        return "1"
    elif len(sub_conds) == 1:
        return sub_conds[0]
    else:
        return f"({' AND '.join(sub_conds)})"

def generate_audit_insert_sql(
    table_name: str,
    rules: List[Dict[str, Any]],
    start_time_str: str,
    end_time_str: str,
    current_run_str: str
) -> Tuple[str, str, Dict[str, Any]]:
    params: Dict[str, Any] = {
        "start": start_time_str,
        "end": end_time_str,
        "match_ts": current_run_str
    }
    
    rule_conds = []
    multi_if_ip = []
    multi_if_port = []
    multi_if_flag = []
    
    for idx, r in enumerate(rules):
        cond = build_rule_sql_condition(r, idx, params)
        rule_conds.append(cond)
        
        # rule_ip param
        ip_val = r.get("ip")
        if ip_val:
            p_ip = f"r_{idx}_ip_val"
            params[p_ip] = str(ip_val)
            multi_if_ip.append(f"{cond}, %({p_ip})s")
        else:
            multi_if_ip.append(f"{cond}, CAST(NULL, 'Nullable(String)')")
            
        # rule_port param
        port_val = r.get("port")
        if port_val is not None and str(port_val).strip() != "":
            p_port = f"r_{idx}_port_val"
            params[p_port] = str(port_val)
            multi_if_port.append(f"{cond}, %({p_port})s")
        else:
            multi_if_port.append(f"{cond}, CAST(NULL, 'Nullable(String)')")
            
        # rule_flag param
        flag_val = r.get("flag", "anomaly")
        p_flag = f"r_{idx}_flag_val"
        params[p_flag] = flag_val
        multi_if_flag.append(f"{cond}, %({p_flag})s")
        
    combined_cond = " OR ".join(f"({c})" for c in rule_conds)
    
    # Build multiIf expressions
    multi_ip_sql = f"multiIf({', '.join(multi_if_ip)}, CAST(NULL, 'Nullable(String)'))"
    multi_port_sql = f"multiIf({', '.join(multi_if_port)}, CAST(NULL, 'Nullable(String)'))"
    multi_flag_sql = f"multiIf({', '.join(multi_if_flag)}, 'anomaly')"
    
    count_sql = f"""
        SELECT count()
        FROM {table_name}
        WHERE ts >= %(start)s AND ts < %(end)s
          AND ({combined_cond})
    """.strip()
    
    insert_sql = f"""
        INSERT INTO matched_flows (
            id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts,
            rule_ip, rule_port, match_flag, match_ts
        )
        SELECT
            id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts,
            {multi_ip_sql} AS rule_ip,
            {multi_port_sql} AS rule_port,
            {multi_flag_sql} AS match_flag,
            toDateTime(%(match_ts)s) AS match_ts
        FROM {table_name}
        WHERE ts >= %(start)s AND ts < %(end)s
          AND ({combined_cond})
    """.strip()
    
    return count_sql, insert_sql, params

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
            
        if start_time_str:
            try:
                last_run_dt = parse_tw_datetime(start_time_str)
            except Exception:
                last_run_dt = now_tw() - timedelta(days=7)
        else:
            cur.execute("SELECT run_ts FROM audit_logs WHERE status = 'success' ORDER BY id DESC LIMIT 1")
            row = cur.fetchone()
            if row:
                last_run_str = row["run_ts"]
                try:
                    last_run_dt = parse_tw_datetime(last_run_str)
                except Exception:
                    last_run_dt = now_tw() - timedelta(days=7)
            else:
                last_run_dt = now_tw() - timedelta(days=7)
            
        current_run_dt = now_tw()
        last_run_str = last_run_dt.strftime("%Y-%m-%d %H:%M:%S")
        current_run_str = current_run_dt.strftime("%Y-%m-%d %H:%M:%S")
        
        print(f"[Audit] Audit range: {last_run_str} to {current_run_str} (Asia/Taipei)", flush=True)
        
        client = get_ch_client()
        # Guarantee matched_flows table exists
        ensure_matched_flows_table(client)
        tables = ["ipfix", "netflow9"]
        total_matched_count = 0
        
        # High Performance Fast-Path: In-database vectorized ClickHouse execution
        try:
            for table in tables:
                count_sql, insert_sql, params = generate_audit_insert_sql(
                    table, rules, last_run_str, current_run_str, current_run_str
                )
                
                # 1. Fast check count in ClickHouse
                count_res = client.query(count_sql, parameters=params)
                matched_in_table = count_res.result_rows[0][0] if count_res.result_rows else 0
                
                print(f"[Audit Fast-Path] Table '{table}': {matched_in_table} flows matched.", flush=True)
                
                if matched_in_table > 0:
                    # 2. Vectorized direct insert within ClickHouse
                    client.command(insert_sql, parameters=params)
                    total_matched_count += matched_in_table
                    
        except Exception as fast_path_err:
            print(f"[Audit Fast-Path Warning] Direct SQL execution encountered error: {fast_path_err}. Falling back to row-by-row matching...", flush=True)
            # Fallback path if direct SQL fails (safety net)
            parsed_rules = parse_rule_criteria(rules)
            all_matched_records = []
            for table in tables:
                query = f"""
                    SELECT id, exporter, proto, src, dst, sport, dport, packets, octets, protocol, json_data, ts
                    FROM {table}
                    WHERE ts >= %(start)s AND ts < %(end)s
                """
                result = client.query(query, parameters={"start": last_run_str, "end": current_run_str})
                column_names = result.column_names
                for row_vals in result.result_rows:
                    flow = dict(zip(column_names, row_vals))
                    matching_rule = check_flow_match(flow, parsed_rules)
                    if matching_rule:
                        flow["rule_ip"] = matching_rule["ip_raw"]
                        flow["rule_port"] = matching_rule["port_raw"]
                        flow["match_flag"] = matching_rule["flag"]
                        flow["match_ts"] = current_run_dt
                        all_matched_records.append(flow)
                        
            if all_matched_records:
                insert_data = [
                    [
                        r["id"], r["exporter"], r["proto"], r["src"], r["dst"],
                        r.get("sport", 0), r.get("dport", 0), r.get("packets", 0),
                        r.get("octets", 0), r.get("protocol"), r["json_data"], r["ts"],
                        r["rule_ip"], r["rule_port"], r["match_flag"], r["match_ts"]
                    ] for r in all_matched_records
                ]
                client.insert("matched_flows", insert_data, column_names=[
                    "id", "exporter", "proto", "src", "dst", "sport", "dport", "packets", "octets", "protocol", "json_data", "ts", "rule_ip", "rule_port", "match_flag", "match_ts"
                ])
            total_matched_count = len(all_matched_records)
            
        cur.execute("INSERT INTO audit_logs (run_ts, status, records_matched, message) VALUES (?, ?, ?, ?)",
                    (current_run_str, "success", total_matched_count, f"Audit completed. Found {total_matched_count} matches."))
        conn.commit()
        conn.close()
        
        print(f"[Audit] Audit success. Matched and saved {total_matched_count} records.", flush=True)
        return {"status": "success", "records_matched": total_matched_count, "message": f"Audit completed. {total_matched_count} records matched."}
        
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
                last_run_dt = parse_tw_datetime(last_run_str)
                if now_tw() - last_run_dt >= timedelta(hours=24):
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

class AuditRuleUpdate(BaseModel):
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
        rule_ips = {r["ip"] for r in rules if r.get("ip")}
        alias_map = resolve_ip_aliases_batch(rule_ips)
        for rule in rules:
            ip = rule.get("ip")
            rule["ip_alias"] = alias_map.get(ip, "") if ip else ""
            port = rule.get("port")
            try:
                rule["port_name"] = port_aliases_cache.get(int(port), "") if port and str(port).isdigit() else ""
            except Exception:
                rule["port_name"] = ""
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
            if ip_val == "":
                ip_val = None
            if port_val == "":
                port_val = None
            
            if not ip_val and not port_val:
                continue
                
            cur.execute("""
                INSERT OR REPLACE INTO audit_rules (ip, port, flag)
                VALUES (?, ?, ?)
            """, (ip_val, port_val, flag))
            imported += 1
            
        conn.commit()
        conn.close()
        return {"status": "success", "message": f"成功匯入 {imported} 條盤查規則。"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/audit/rules")
def create_audit_rule(rule: AuditRuleCreate):
    ip_val = rule.ip.strip() if rule.ip else None
    port_val = rule.port.strip() if rule.port else None
    flag_val = rule.flag.strip().lower()
    
    if flag_val not in ("watch", "anomaly"):
        raise HTTPException(status_code=400, detail="標記必須為 'watch' 或 'anomaly'")
        
    if not ip_val and not port_val:
        raise HTTPException(status_code=400, detail="IP 與 Port 至少需填寫其中一項。")
        
    if ip_val and not validate_ip_or_cidr(ip_val):
        raise HTTPException(status_code=400, detail="無效的 IP 或 CIDR 位址格式。")
        
    if port_val and not validate_port_or_range(port_val):
        raise HTTPException(status_code=400, detail="無效的 Port 或 Port 範圍格式（例如 '80' 或 '80-443'）。")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        if ip_val is None:
            ip_clause = "(ip IS NULL OR ip = '')"
            ip_params = []
        else:
            ip_clause = "ip = ?"
            ip_params = [ip_val]

        if port_val is None:
            port_clause = "(port IS NULL OR port = '')"
            port_params = []
        else:
            port_clause = "port = ?"
            port_params = [port_val]

        cur.execute(f"SELECT id FROM audit_rules WHERE {ip_clause} AND {port_clause}", ip_params + port_params)
        if cur.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="已存在相同 IP/CIDR 與 Port 的規則，不可重複設定。")
            
        cur.execute("INSERT INTO audit_rules (ip, port, flag, created_at) VALUES (?, ?, ?, ?)", (ip_val, port_val, flag_val, now_tw_str()))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "盤查規則新增成功。"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/audit/rules/{rule_id}")
def update_audit_rule(rule_id: int, rule: AuditRuleUpdate):
    ip_val = rule.ip.strip() if rule.ip else None
    port_val = rule.port.strip() if rule.port else None
    flag_val = rule.flag.strip().lower()
    
    if flag_val not in ("watch", "anomaly"):
        raise HTTPException(status_code=400, detail="標記必須為 'watch' 或 'anomaly'")
        
    if not ip_val and not port_val:
        raise HTTPException(status_code=400, detail="IP 與 Port 至少需填寫其中一項。")
        
    if ip_val and not validate_ip_or_cidr(ip_val):
        raise HTTPException(status_code=400, detail="無效的 IP 或 CIDR 位址格式。")
        
    if port_val and not validate_port_or_range(port_val):
        raise HTTPException(status_code=400, detail="無效的 Port 或 Port 範圍格式（例如 '80' 或 '80-443'）。")
        
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        
        cur.execute("SELECT id FROM audit_rules WHERE id = ?", (rule_id,))
        if not cur.fetchone():
            conn.close()
            raise HTTPException(status_code=404, detail="找不到欲修改的規則。")
            
        if ip_val is None:
            ip_clause = "(ip IS NULL OR ip = '')"
            ip_params = []
        else:
            ip_clause = "ip = ?"
            ip_params = [ip_val]

        if port_val is None:
            port_clause = "(port IS NULL OR port = '')"
            port_params = []
        else:
            port_clause = "port = ?"
            port_params = [port_val]

        cur.execute(f"SELECT id FROM audit_rules WHERE {ip_clause} AND {port_clause} AND id != ?", ip_params + port_params + [rule_id])
        if cur.fetchone():
            conn.close()
            raise HTTPException(status_code=400, detail="已存在相同 IP/CIDR 與 Port 的規則，不可重複設定。")
            
        cur.execute("""
            UPDATE audit_rules 
            SET ip = ?, port = ?, flag = ?
            WHERE id = ?
        """, (ip_val, port_val, flag_val, rule_id))
        conn.commit()
        conn.close()
        return {"status": "success", "message": "盤查規則已成功更新。"}
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
    def format_tw_str(dt_str: str) -> str:
        if not dt_str or dt_str == "Never":
            return "Never"
        try:
            dt = parse_tw_datetime(dt_str)
            return dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return dt_str

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
        
        last_run_tw = "Never"
        next_run_tw = "Immediately"
        status = "none"
        records_matched = 0
        message = "No audit has run yet."
        
        if last_log:
            last_run_tw = format_tw_str(last_log["run_ts"])
            status = last_log["status"]
            records_matched = last_log["records_matched"]
            message = last_log["message"]
            
        if last_success:
            dt = parse_tw_datetime(last_success["run_ts"])
            next_dt = dt + timedelta(hours=24)
            next_run_tw = next_dt.strftime("%Y-%m-%d %H:%M:%S")
            
        return {
            "run_ts": last_run_tw,
            "next_run_ts": next_run_tw,
            "status": status,
            "records_matched": records_matched,
            "message": message
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches/stats")
def get_audit_matches_stats(
    ip: Optional[str] = Query(None),
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    alias: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    proto: Optional[str] = Query(None),
    flag: Optional[str] = Query(None),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'")
):
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        where_clauses = []
        params = {}

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "ms_alias"))
        
        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "audit_stats_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
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
            if proto:
                proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
                proto_clauses = []
                for idx, p in enumerate(proto_parts):
                    key = f"proto_p_{idx}"
                    params[key] = p
                    p_num = None
                    for num, name in PROTO_NAME_MAP.items():
                        if name.upper() == p.upper():
                            p_num = num
                            break
                    if p_num is not None:
                        num_key = f"proto_num_{idx}"
                        params[num_key] = p_num
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    elif p.isdigit():
                        num_key = f"proto_num_{idx}"
                        params[num_key] = int(p)
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    else:
                        proto_clauses.append(f"proto ILIKE %({key})s")
                if proto_clauses:
                    where_clauses.append(f"({' OR '.join(proto_clauses)})")
        if flag:
            where_clauses.append("match_flag = %(flag)s")
            params["flag"] = flag.strip().lower()
            
        where_sql = ""
        if where_clauses:
            where_sql = "WHERE " + " AND ".join(where_clauses)
            
        where_sport = f"{where_sql} AND sport IS NOT NULL" if where_sql else "WHERE sport IS NOT NULL"
        where_dport = f"{where_sql} AND dport IS NOT NULL" if where_sql else "WHERE dport IS NOT NULL"

        f_totals = ch_query_executor.submit(
            _run_ch_query,
            f"SELECT COUNT() as total_flows, SUM(packets) as total_packets, SUM(octets) as total_bytes FROM matched_flows {where_sql}",
            params
        )
        f_top_src = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT src, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM matched_flows
            {where_sql}
            GROUP BY src
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_dst = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT dst, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM matched_flows
            {where_sql}
            GROUP BY dst
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_sport = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT sport, SUM(octets) as bytes, COUNT() as flows
            FROM matched_flows
            {where_sport}
            GROUP BY sport
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_dport = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT dport, SUM(octets) as bytes, COUNT() as flows
            FROM matched_flows
            {where_dport}
            GROUP BY dport
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_top_ports = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT port, SUM(octets) as bytes, COUNT() as flows
            FROM (
                SELECT sport as port, octets FROM matched_flows {where_sport}
                UNION ALL
                SELECT dport as port, octets FROM matched_flows {where_dport}
            )
            GROUP BY port
            ORDER BY bytes DESC
            LIMIT 10
            """,
            params
        )
        f_protocols = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT proto as name, COUNT() as count, SUM(octets) as bytes
            FROM matched_flows
            {where_sql}
            GROUP BY name
            ORDER BY count DESC
            """,
            params
        )
        f_ip_protos = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT protocol as name_num, COUNT() as count, SUM(octets) as bytes
            FROM matched_flows
            {where_sql}
            GROUP BY name_num
            ORDER BY count DESC
            """,
            params
        )
        f_flags = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT match_flag as name, COUNT() as count, SUM(octets) as bytes
            FROM matched_flows
            {where_sql}
            GROUP BY name
            ORDER BY count DESC
            """,
            params
        )
        f_top_pairs = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT src, dst, SUM(octets) as bytes, COUNT() as flows
            FROM matched_flows
            {where_sql}
            GROUP BY src, dst
            ORDER BY bytes DESC
            LIMIT 1000
            """,
            params
        )
        f_range = ch_query_executor.submit(
            _run_ch_query,
            f"SELECT min(ts), max(ts) FROM matched_flows {where_sql}",
            params
        )

        # 8. Traffic over time (launch immediately once range finishes)
        range_res = f_range.result()
        min_ts, max_ts = range_res.result_rows[0]
        
        time_format = "%Y-%m-%d"
        ch_group_fn = "toStartOfDay(ts + INTERVAL 8 HOUR)"
        if min_ts and max_ts:
            diff_secs = (max_ts - min_ts).total_seconds()
            if diff_secs < 172800: # < 48 hours
                time_format = "%Y-%m-%d %H:00"
                ch_group_fn = "toStartOfHour(ts + INTERVAL 8 HOUR)"
                
        f_time = ch_query_executor.submit(
            _run_ch_query,
            f"""
            SELECT {ch_group_fn} as time_bin, SUM(octets) as bytes, SUM(packets) as packets, COUNT() as flows
            FROM matched_flows
            {where_sql}
            GROUP BY time_bin
            ORDER BY time_bin ASC
            """,
            params
        )

        # Collect parallel results
        res = f_totals.result()
        totals = dict(zip(res.column_names, res.result_rows[0]))
        total_flows = totals["total_flows"] or 0
        total_packets = totals["total_packets"] or 0
        total_bytes = totals["total_bytes"] or 0

        res = f_top_src.result()
        top_sources = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_dst.result()
        top_destinations = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_sport.result()
        top_source_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_dport.result()
        top_destination_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_top_ports.result()
        top_ports = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_protocols.result()
        protocols = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_ip_protos.result()
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

        res = f_flags.result()
        flags = [dict(zip(res.column_names, r)) for r in res.result_rows]

        res = f_time.result()
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

        # Calculate Top IP Aliases (Bidirectional aggregated, deduplicated if both endpoints share same alias)
        res_pairs = f_top_pairs.result()
        pair_rows = [dict(zip(res_pairs.column_names, r)) for r in res_pairs.result_rows]
        pair_ips = set()
        for r in pair_rows:
            if r.get("src"):
                pair_ips.add(r["src"])
            if r.get("dst"):
                pair_ips.add(r["dst"])
        alias_map_pairs = resolve_ip_aliases_batch(pair_ips)
        alias_aggregated = {}
        for r in pair_rows:
            s_alias = alias_map_pairs.get(r.get("src"))
            d_alias = alias_map_pairs.get(r.get("dst"))
            matched_aliases = set()
            if s_alias:
                matched_aliases.add(s_alias)
            if d_alias:
                matched_aliases.add(d_alias)
            for al in matched_aliases:
                if al not in alias_aggregated:
                    alias_aggregated[al] = {"name": al, "bytes": 0, "flows": 0}
                alias_aggregated[al]["bytes"] += (r.get("bytes") or 0)
                alias_aggregated[al]["flows"] += (r.get("flows") or 0)
        top_aliases = sorted(alias_aggregated.values(), key=lambda x: x["bytes"], reverse=True)[:10]

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
            "top_aliases": top_aliases,
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
    ip: Optional[str] = Query(None),
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    alias: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    proto: Optional[str] = Query(None),
    flag: Optional[str] = Query(None),
    conditions: Optional[str] = Query(None, description="JSON string of dynamic conditions list"),
    logic: str = Query("AND", description="Combination logic: 'AND' or 'OR'"),
    sort_by: str = Query("match_ts"),
    sort_order: str = Query("desc")
):
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        where_clauses = []
        params = {}

        if alias:
            where_clauses.append(build_alias_where_clause("any", alias, params, "m_alias"))
        
        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "audit_dyn")
        if dyn_clause:
            where_clauses.append(dyn_clause)
        else:
            if ip:
                src_c = build_ip_where_clause("src", ip, params, "ip_src")
                dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
                where_clauses.append(f"({src_c} OR {dst_c})")
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
            if proto:
                proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
                proto_clauses = []
                for idx, p in enumerate(proto_parts):
                    key = f"proto_p_{idx}"
                    params[key] = p
                    p_num = None
                    for num, name in PROTO_NAME_MAP.items():
                        if name.upper() == p.upper():
                            p_num = num
                            break
                    if p_num is not None:
                        num_key = f"proto_num_{idx}"
                        params[num_key] = p_num
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    elif p.isdigit():
                        num_key = f"proto_num_{idx}"
                        params[num_key] = int(p)
                        proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                    else:
                        proto_clauses.append(f"proto ILIKE %({key})s")
                if proto_clauses:
                    where_clauses.append(f"({' OR '.join(proto_clauses)})")
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
            "src", "sport", "dst", "dport", "proto", "packets", "octets", "exporter"
        }
        if sort_by not in allowed_cols:
            sort_by = "ts"
            
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
            if r.get("exporter"):
                ips_to_resolve.add(r["exporter"])
            if r.get("rule_ip"):
                ips_to_resolve.add(r["rule_ip"])
                
        # Get DNS and IP Aliases mappings in batch
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)
        for r in records:
            src_ip = r.get("src")
            dst_ip = r.get("dst")
            exporter_ip = r.get("exporter")
            r["src_domain"] = alias_map.get(src_ip) or dns_map.get(src_ip, "")
            r["dst_domain"] = alias_map.get(dst_ip) or dns_map.get(dst_ip, "")
            r["exporter_alias"] = alias_map.get(exporter_ip) or dns_map.get(exporter_ip, "")
            r["sport_name"] = port_aliases_cache.get(r.get("sport"), "") if r.get("sport") is not None else ""
            r["dport_name"] = port_aliases_cache.get(r.get("dport"), "") if r.get("dport") is not None else ""
            rule_ip = r.get("rule_ip")
            r["rule_ip_alias"] = alias_map.get(rule_ip, "") if rule_ip else ""
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
        ensure_matched_flows_table(client)
        client.command("TRUNCATE TABLE matched_flows")
        return {"status": "success", "message": "Permanently matched records cleared."}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/audit/matches/{match_id}")
def delete_single_audit_match(match_id: str):
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        client.command("ALTER TABLE matched_flows DELETE WHERE id = %(id)s", parameters={"id": match_id})
        return {"status": "success", "message": f"Match record {match_id} deleted."}
    except Exception as e:
        reset_ch_client()
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/matches/export")
def export_audit_matches(
    ip: Optional[str] = Query(None),
    src: Optional[str] = Query(None),
    dst: Optional[str] = Query(None),
    sport: Optional[int] = Query(None),
    dport: Optional[int] = Query(None),
    port: Optional[int] = Query(None),
    proto: Optional[str] = Query(None),
    flag: Optional[str] = Query(None),
    conditions: Optional[str] = Query(None),
    logic: str = Query("AND")
):
    import io
    import csv
    from fastapi.responses import StreamingResponse
    
    try:
        client = get_ch_client()
        ensure_matched_flows_table(client)
        where_clauses = []
        params = {}
        
        dyn_clause = parse_conditions_where_clause(conditions, logic, params, "audit_exp_dyn")
        if dyn_clause:
            where_clauses.append(f"({dyn_clause})")
            
        if ip:
            src_c = build_ip_where_clause("src", ip, params, "ip_src")
            dst_c = build_ip_where_clause("dst", ip, params, "ip_dst")
            where_clauses.append(f"({src_c} OR {dst_c})")
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
        if proto:
            proto_parts = [p.strip() for p in proto.split(",") if p.strip()]
            proto_clauses = []
            for idx, p in enumerate(proto_parts):
                key = f"proto_p_{idx}"
                params[key] = p
                p_num = None
                for num, name in PROTO_NAME_MAP.items():
                    if name.upper() == p.upper():
                        p_num = num
                        break
                if p_num is not None:
                    num_key = f"proto_num_{idx}"
                    params[num_key] = p_num
                    proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                elif p.isdigit():
                    num_key = f"proto_num_{idx}"
                    params[num_key] = int(p)
                    proto_clauses.append(f"(proto ILIKE %({key})s OR protocol = %({num_key})s)")
                else:
                    proto_clauses.append(f"proto ILIKE %({key})s")
            if proto_clauses:
                where_clauses.append(f"({' OR '.join(proto_clauses)})")
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
        
        # Collect unique IPs to resolve domains and aliases in batch
        ips_to_resolve = set()
        for row in data_result.result_rows:
            r = dict(zip(column_names, row))
            if r.get("src"):
                ips_to_resolve.add(r["src"])
            if r.get("dst"):
                ips_to_resolve.add(r["dst"])
            if r.get("exporter"):
                ips_to_resolve.add(r["exporter"])
            if r.get("rule_ip"):
                ips_to_resolve.add(r["rule_ip"])
        dns_map = get_dns_mappings(ips_to_resolve)
        alias_map = resolve_ip_aliases_batch(ips_to_resolve)
        
        # CSV generator
        def csv_generator():
            yield "\ufeff"
            output = io.StringIO()
            writer = csv.writer(output)
            
            # CSV Headers
            headers = [
                "Flow Time", "Flag", "Collector IP", "Collector IP Alias", "Audit Time", "Matched IP Rule", "Matched Port Rule",
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
                
                # Collector IP and alias
                exporter_ip = r.get("exporter") or ""
                exporter_alias = alias_map.get(exporter_ip) or dns_map.get(exporter_ip, "")

                # DNS and Aliases resolution
                src_ip = r["src"]
                dst_ip = r["dst"]
                src_domain = alias_map.get(src_ip) or dns_map.get(src_ip, "")
                dst_domain = alias_map.get(dst_ip) or dns_map.get(dst_ip, "")
                
                sport_val = r["sport"]
                dport_val = r["dport"]
                sport_name = port_aliases_cache.get(sport_val, "")
                dport_name = port_aliases_cache.get(dport_val, "")
                
                p_name = PROTO_NAME_MAP.get(r["protocol"], f"UNKNOWN ({r['protocol']})" if r["protocol"] is not None else "N/A")
                rule_ip = r["rule_ip"]
                rule_ip_alias = alias_map.get(rule_ip, "") if rule_ip else ""
                rule_ip_val = f"{rule_ip} ({rule_ip_alias})" if rule_ip and rule_ip_alias else (rule_ip or "(任意)")
                row_data = [
                    f_ts, flag_val, exporter_ip, exporter_alias, m_ts, rule_ip_val, r["rule_port"] or "(任意)",
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
