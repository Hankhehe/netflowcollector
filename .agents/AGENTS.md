# Netflow Collector Workspace Rules

These project-scoped rules apply to all coding work in this codebase.

## 🏷️ IP & Port Alias Resolution Policy

Always resolve and display IP aliases, IP domain reverse DNS mappings, and port aliases in the frontend UI whenever they are available.

### 1. Data Sources
- **IP Aliases**: Loaded from the SQLite `ip_aliases` table (via `ip_aliases_cache`). Supports CIDR block input (e.g. `192.168.1.0/24`) and uses longest prefix match resolution (via `resolve_ip_alias`).
- **IP Reverse DNS**: Loaded from the SQLite `dns_cache` table (via `get_dns_mappings()`).
- **Port Aliases**: Loaded from the SQLite `port_aliases` table (via `port_aliases_cache`).

### 2. Implementation Guidelines
- **UI Tables and Lists**:
  - For IP columns (including source, destination, and matched rule IPs), if a custom alias or domain reverse DNS is resolved, it must be displayed as a subtitle (`.domain-subtext`) below the raw IP.
  - For Port columns (source, destination, and matched rule ports), if a custom alias name is resolved, it must be displayed as a subtitle below the port number.
- **UI Charts**:
  - IP labels (X-axis of Top Sources / Top Destinations charts) must be formatted as `IP (Alias/Domain)` using the `formatChartIPLabel` helper. Overly long domain names must be truncated to prevent overlap.
  - Port labels (X-axis of Top Ports charts) must be formatted as `Port (Alias)` if the port name exists in `port_aliases_cache`.
- **Backend API Endpoints**:
  - Ensure all matches, stats, and rule query endpoints (e.g., `/api/flows/stats`, `/api/audit/matches/stats`, `/api/audit/matches`, `/api/audit/rules`) return resolved alias and domain information inside each record.
