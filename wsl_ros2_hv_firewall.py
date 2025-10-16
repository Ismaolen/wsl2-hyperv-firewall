#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSL → Windows Hyper-V Firewall Rule Manager
Creates/Deletes Hyper-V firewall rules via **powershell.exe** from within WSL.

**Features:**

* Prefix (Default: WSL-ROS2)
* Protocols: TCP/UDP/ICMPv4
* Direction: In/Out/Both
* Configurable ports (TCP/UDP only)
* Multiple IPs (comma-separated)
* Idempotent: creates only if not existing (no pre-remove)
* Persistence in `./wsl_ros2_firewall_rules.json`
* `--dry-run` for preview

**Requires:** Windows administrator privileges.

"""

import argparse
import json
import subprocess
import sys
import shutil
from pathlib import Path
from datetime import datetime, timezone
import ipaddress

DB_FILE = Path.cwd() / "wsl_ros2_firewall_rules.json"

DEFAULT_PREFIX = "WSL-ROS2"
DEFAULT_VM_CREATOR_ID = "{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}"
DEFAULT_LOCAL_PORTS = "0-65535"
DEFAULT_REMOTE_PORTS = "0-65535"



def print_examples():
    import sys
    # ANSI colors (auto-disabled when not a TTY)
    RESET = "\033[0m"
    BOLD = "\033[1m"
    PINK = "\033[38;5;213m"
    CYAN = "\033[38;5;45m"
    GREEN = "\033[38;5;114m"
    YELLOW = "\033[38;5;229m"
    ORANGE = "\033[38;5;214m"
    BLUE = "\033[38;5;39m"
    MAGENTA = "\033[38;5;200m"
    DIM = "\033[2m"

    if not sys.stdout.isatty():
        RESET = BOLD = PINK = CYAN = GREEN = YELLOW = ORANGE = BLUE = MAGENTA = DIM = ""

    sep = f"{MAGENTA}{'─'*60}{RESET}"
    title = f"{BOLD}{PINK}Examples (from WSL){RESET}"

    print(f"""
{sep}
{title}
{sep}

{DIM}Note on persistence:{RESET}
By default, no JSON DB writes happen. Add {YELLOW}--db{RESET} (before or after the subcommand)
to also update {BOLD}./wsl_ros2_firewall_rules.json{RESET}.
Examples:
  {ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}--db search{RESET}
  {ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {YELLOW}--db{RESET}

{GREEN}# 1) All protocols (TCP/UDP/ICMP) IN+OUT for one IP (default ports 0-65535){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {CYAN}--ip {BLUE}192.168.0.213{RESET}

{GREEN}# 2) TCP-IN and UDP-OUT for two IPs with specific ports{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213,192.168.0.214 {RESET}\\
  {CYAN}--protocol {BLUE}tcp,udp {RESET}\\
  {CYAN}--direction {BLUE}both {RESET}\\
  {CYAN}--local-ports {BLUE}11311,8080 {RESET}\\
  {CYAN}--remote-ports {BLUE}11311,8080{RESET}

{GREEN}# 3) ICMP-IN only (no ports){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {CYAN}--ip {BLUE}192.168.0.213 {CYAN}--protocol {BLUE}icmp {CYAN}--direction {BLUE}in{RESET}

{GREEN}# 4) Delete by exact name{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {CYAN}--name {BLUE}WSL-ROS2-TCP-IN-192.168.0.213{RESET}

{GREEN}# 4b) Multiple names / wildcards{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {CYAN}--name {BLUE}'WSL-PI*,WSL-ROS2-UDP-OUT-*'{RESET}

{GREEN}# 4c) Delete by filters (like search) with preview limit{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {CYAN}--prefix {BLUE}WSL-* {CYAN}--protocol {BLUE}udp {CYAN}--direction {BLUE}out{RESET}

{GREEN}# 4d) Really delete lots of matches (override safety limit){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {CYAN}--prefix {BLUE}WSL-* {CYAN}--all{RESET}

{GREEN}# 4e) Show what would be deleted (dry run){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {CYAN}--name {BLUE}WSL-ROS2-* {CYAN}--dry-run{RESET}


{GREEN}# 5) Create: dry run only (no changes){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {CYAN}--ip {BLUE}192.168.0.213 {CYAN}--dry-run{RESET}

{GREEN}# 6) Search all WSL Hyper-V rules{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search{RESET}
{DIM}# Persist results to the JSON DB as well:{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}--db search{RESET}


{DIM}# ───────── More handy examples ─────────{RESET}

{GREEN}# 7) Create UDP-OUT only (e.g., telemetry){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {CYAN}--ip {BLUE}192.168.0.213 {CYAN}--protocol {BLUE}udp {CYAN}--direction {BLUE}out{RESET}

{GREEN}# 8) Create TCP-IN for fixed ports (ROS Master 11311 + Web UI 8080){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213 {RESET}\\
  {CYAN}--protocol {BLUE}tcp {RESET}\\
  {CYAN}--direction {BLUE}in {RESET}\\
  {CYAN}--local-ports {BLUE}11311,8080 {RESET}\\
  {CYAN}--remote-ports {BLUE}11311,8080{RESET}

{GREEN}# 9) Remove everything for two IPs (all protocols, IN+OUT){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213,192.168.0.214 {RESET}\\
  {CYAN}--protocol {BLUE}tcp,udp,icmp {RESET}\\
  {CYAN}--direction {BLUE}both{RESET}

{GREEN}# 10) Delete UDP-OUT rules for two IPs only{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213,192.168.0.214 {RESET}\\
  {CYAN}--protocol {BLUE}udp {RESET}\\
  {CYAN}--direction {BLUE}out{RESET}

{GREEN}# 11) Delete ICMP-IN rules only{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {CYAN}--ip {BLUE}192.168.0.213 {CYAN}--protocol {BLUE}icmp {CYAN}--direction {BLUE}in{RESET}

{GREEN}# 12) Use a different prefix (e.g., WSL-PI instead of WSL-ROS2){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {CYAN}--ip {BLUE}192.168.0.213 {CYAN}--prefix {BLUE}WSL-PI{RESET}
{DIM}# ... and delete them again:{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}delete {CYAN}--ip {BLUE}192.168.0.213 {CYAN}--prefix {BLUE}WSL-PI{RESET}

{GREEN}# 13) Use a different VMCreatorId (GUID){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213 {RESET}\\
  {CYAN}--vmcreator-id {BLUE}'{{00000000-0000-0000-0000-000000000000}}'{RESET}

{GREEN}# 14) Test run: all protocols IN+OUT (show only){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}create {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213 {RESET}\\
  {CYAN}--protocol {BLUE}tcp,udp,icmp {RESET}\\
  {CYAN}--direction {BLUE}both {RESET}\\
  {CYAN}--dry-run{RESET}


{DIM}# ───────── Search / filter examples ─────────{RESET}

{GREEN}# 15) Show all WSL-ROS2 Hyper-V rules (default prefix){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search{RESET}

{GREEN}# 16) With a different prefix (e.g., WSL-PI){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--prefix {BLUE}WSL-PI{RESET}

{GREEN}# 17) Name contains 'TCP-IN'{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--name-contains {BLUE}TCP-IN{RESET}

{GREEN}# 18) Filter by a specific IP{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--ip {BLUE}192.168.0.213{RESET}

{GREEN}# 19) Filter by multiple IPs{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213,192.168.0.214{RESET}

{GREEN}# 20) Show UDP rules only{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--protocol {BLUE}udp{RESET}

{GREEN}# 21) Combine TCP and ICMP{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--protocol {BLUE}tcp,icmp{RESET}

{GREEN}# 22) Inbound only{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--direction {BLUE}in{RESET}

{GREEN}# 23) Outbound only{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--direction {BLUE}out{RESET}

{GREEN}# 24) Combination: TCP-IN for IP 192.168.0.213{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213 {RESET}\\
  {CYAN}--protocol {BLUE}tcp {RESET}\\
  {CYAN}--direction {BLUE}in{RESET}

{GREEN}# 25) Filter by VMCreatorId (GUID){RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {CYAN}--vmcreator-id {BLUE}'{{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}}'{RESET}

{GREEN}# 26) Complex filter: different prefix + name contains 'UDP' + two IPs + both{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {RESET}\\
  {CYAN}--prefix {BLUE}WSL-PI {RESET}\\
  {CYAN}--name-contains {BLUE}UDP {RESET}\\
  {CYAN}--ip {BLUE}192.168.0.213,192.168.0.214 {RESET}\\
  {CYAN}--direction {BLUE}both{RESET}

{GREEN}# 27) Paginate output{RESET}
{ORANGE}$ {YELLOW}python3 wsl_ros2_hv_firewall.py {CYAN}search {ORANGE}| {YELLOW}less -R{RESET}

{sep}
""")





def ensure_powershell_available():
    # In WSL, powershell.exe should be callable.
    if shutil.which("powershell.exe") is None:
        sys.exit("ERROR: 'powershell.exe' was not found. Please ensure WSL is allowed to run " \
        "Windows tools and that powershell.exe is in the PATH.")

def load_db():
    if DB_FILE.exists():
        try:
            return json.loads(DB_FILE.read_text(encoding="utf-8"))
        except Exception:
            return []
    return []

def save_db(entries):
    DB_FILE.write_text(json.dumps(entries, indent=2, ensure_ascii=False), encoding="utf-8")



def upsert_many(entries, enable_db=True):
    """Upsert multiple entries by name and save once."""
    if not enable_db:
        return
    db = load_db()
    by_name = {e.get("name"): e for e in db if e.get("name")}
    for e in entries:
        by_name[e["name"]] = e
    save_db(list(by_name.values()))

def _qps(s: str) -> str:
    """For PowerShell strings: double single quotes."""
    return (s or "").replace("'", "''")











def validate_ip_list(ip_list_str):
    # Allows multiple IPs, comma-separated. Validates IPv4/IPv6.
    ips = []
    for token in [s.strip() for s in ip_list_str.split(",") if s.strip()]:
        try:
            
            ipaddress.ip_address(token)
            ips.append(token)
        except ValueError:
            sys.exit(f"ERROR: Invalid IP address: {token}")
    if not ips:
        sys.exit("ERROR: At least one valid IP address must be provided.")
    return ips

def parse_protocols(proto_str):
    allowed = {"tcp", "udp", "icmp"}
    result = []
    for p in [s.strip().lower() for s in proto_str.split(",") if s.strip()]:
        if p not in allowed:
            sys.exit(f"ERROR: Invalid protocol '{p}'. Allowed: tcp, udp, icmp")
        result.append(p)
    # Standard: alle
    return result or ["tcp", "udp", "icmp"]

def parse_direction(direction_str):
    direction_str = direction_str.strip().lower()
    if direction_str not in {"in", "out", "both"}:
        sys.exit("ERROR: --direction must be in|out|both.")
    if direction_str == "both":
        return ["Inbound", "Outbound"]
    return ["Inbound"] if direction_str == "in" else ["Outbound"]

def proto_to_ps(proto):
    if proto == "icmp":
        return "ICMPv4"
    return proto.upper()

def build_rule_name(prefix, proto, direction, ip):
    # Example: WSL-ROS2-TCP-IN-192.168.0.213
    dir_tag = "IN" if direction == "Inbound" else "OUT"
    return f"{prefix}-{proto.upper()}-{dir_tag}-{ip}"

def build_display_name(proto, direction, ip):
    dir_tag = "IN" if direction == "Inbound" else "OUT"
    pretty_proto = "ICMP" if proto.lower() == "icmp" else proto.upper()
    return f"ROS2 {pretty_proto} {dir_tag} {ip}"

def run_ps(ps_command, dry_run=False):
    cmd = [
        "powershell.exe",
        "-NoLogo",
        "-NonInteractive",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-Command", ps_command
    ]
    if dry_run:
        print("[DRY-RUN] ", " ".join(cmd))
        return 0, "", ""
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def _render_table(rows):
    # rows: list of dicts (Name, Protocol, Direction, RemoteAddresses, LocalPorts, RemotePorts, DisplayName, VMCreatorId)
    cols = ["Name", "Protocol", "Direction", "RemoteAddresses", "LocalPorts", "RemotePorts", "DisplayName", "VMCreatorId"]

    # Determine column widths
    widths = {c: len(c) for c in cols}
    for r in rows:
        for c in cols:
            v = r.get(c, "")
            if v is None:
                v = ""
            widths[c] = max(widths[c], len(str(v)))

    # Header + divider
    header = " ".join(f"{c:{widths[c]}}" for c in cols)
    divider = " ".join("-" * widths[c] for c in cols)
    print(header)
    print(divider)

    # Rows
    for r in rows:
        vals = []
        for c in cols:
            v = r.get(c, "")
            # Like Format-Table: show ports as empty, not "None" or "-"
            v = "" if v in (None, "Any", "any") else str(v)
            vals.append(f"{v:{widths[c]}}")
        print(" ".join(vals))


def remove_rule_if_exists(name, dry_run=False):
    # Only remove if the rule exists -> avoids Exit Code 1
    ps = (
        f"$r = Get-NetFirewallHyperVRule -Name '{name}' -ErrorAction SilentlyContinue; "
        f"if ($r) {{ Remove-NetFirewallHyperVRule -Name '{name}' -ErrorAction Stop | Out-Null }}"
    )
    code, out, err = run_ps(ps, dry_run=dry_run)
    if code != 0 and not dry_run:
        print(f"Warning: removing rule '{name}' returned code {code}: {err.strip()}", file=sys.stderr)


def create_rule(name, display_name, direction, proto, ip, vmcreator_id,
                local_ports, remote_ports, dry_run=False):
    ps_proto = proto_to_ps(proto)

    # Only pass ports for TCP/UDP
    port_args = ""
    if proto in ("tcp", "udp"):
        port_args = (
            f"-LocalPorts '{local_ports}' "
            f"-RemotePorts '{remote_ports}' "
        )

    ps = (
        f"$name = '{name}'; "
        f"$r = Get-NetFirewallHyperVRule -Name $name -ErrorAction SilentlyContinue; "
        f"if (-not $r) {{ "
        f"  New-NetFirewallHyperVRule "
        f"    -Name '{name}' "
        f"    -DisplayName '{display_name}' "
        f"    -Direction {direction} "
        f"    -VMCreatorId '{vmcreator_id}' "
        f"    -Protocol {ps_proto} "
        f"    -RemoteAddresses '{ip}' "
        f"    {port_args}"
        f"    -Action Allow -ErrorAction Stop | Out-Null; "
        f"  Write-Output 'CREATED' "
        f"}} else {{ "
        f"  Write-Output 'EXISTS' "
        f"}}"
    )

    code, out, err = run_ps(ps, dry_run=dry_run)
    if code != 0 and not dry_run:
        sys.exit(f"ERROR: Creating rule '{name}' failed:\n{err}")
    return (out or "").strip()





def persist_add(entry):
    db = load_db()
    # Falls gleicher Name schon existiert → ersetzen
    db = [e for e in db if e.get("name") != entry["name"]]
    db.append(entry)
    save_db(db)

def persist_remove_by_name(name):
    db = load_db()
    new_db = [e for e in db if e.get("name") != name]
    save_db(new_db)

def make_entries(prefix, ips, protos, directions, vmcreator_id, local_ports, remote_ports):
    entries = []
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    for ip in ips:
        for proto in protos:
            for direction in directions:
                name = build_rule_name(prefix, proto, direction, ip)
                display = build_display_name(proto, direction, ip)
                entry = {
                    "name": name,
                    "displayName": display,
                    "direction": direction,
                    "protocol": proto_to_ps(proto),
                    "remoteAddresses": ip,
                    "localPorts": (local_ports if proto in ("tcp", "udp") else None),
                    "remotePorts": (remote_ports if proto in ("tcp", "udp") else None),
                    "action": "Allow",
                    "vmCreatorId": vmcreator_id,
                    "createdAt": now
                }
                entries.append(entry)
    return entries

def do_create(args):
    ensure_powershell_available()
    ips = validate_ip_list(args.ip)
    protos = parse_protocols(args.protocol)
    directions = parse_direction(args.direction)

    entries = make_entries(
        args.prefix, ips, protos, directions,
        args.vmcreator_id, args.local_ports, args.remote_ports
    )

    if args.dry_run:
        for e in entries:
            print(f"[DRY-RUN] would create (if not existing): {e['name']}")
        return

    # ---- PowerShell: create all rules in ONE pass (if not existing) ----
    # Build a PS array of hashtables @(...)
    items = []
    for e in entries:
        items_kv = [
            f"Name='{_qps(e['name'])}'",
            f"DisplayName='{_qps(e['displayName'])}'",
            f"Direction='{_qps(e['direction'])}'",
            f"VMCreatorId='{_qps(e['vmCreatorId'])}'",
            f"Protocol='{_qps(e['protocol'])}'",
            f"RemoteAddresses='{_qps(e['remoteAddresses'])}'",
        ]
        # Ports nur mitgeben, wenn TCP/UDP
        if e["protocol"] in ("TCP", "UDP"):
            if e.get("localPorts"):
                items_kv.append(f"LocalPorts='{_qps(e['localPorts'])}'")
            if e.get("remotePorts"):
                items_kv.append(f"RemotePorts='{_qps(e['remotePorts'])}'")
        items.append("@{" + "; ".join(items_kv) + "}")

    ps = (
        "$entries = @(" + ",".join(items) + "); "
        "foreach ($e in $entries) { "
        "  $exists = Get-NetFirewallHyperVRule -Name $e.Name -ErrorAction SilentlyContinue; "
        "  if (-not $exists) { "
        "    $portArgs = @{}; "
        "    if ($e.Protocol -eq 'TCP' -or $e.Protocol -eq 'UDP') { "
        "      if ($e.LocalPorts)  { $portArgs['LocalPorts']  = $e.LocalPorts } "
        "      if ($e.RemotePorts) { $portArgs['RemotePorts'] = $e.RemotePorts } "
        "    } "
        "    New-NetFirewallHyperVRule "
        "      -Name $e.Name "
        "      -DisplayName $e.DisplayName "
        "      -Direction $e.Direction "
        "      -VMCreatorId $e.VMCreatorId "
        "      -Protocol $e.Protocol "
        "      -RemoteAddresses $e.RemoteAddresses "
        "      @portArgs -Action Allow -ErrorAction Stop | Out-Null; "
        "    Write-Output ('CREATED ' + $e.Name) "
        "  } else { "
        "    Write-Output ('EXISTS ' + $e.Name) "
        "  } "
        "}"
    )

    code, out, err = run_ps(ps, dry_run=False)
    if code != 0:
        sys.exit(f"ERROR: Erstellen fehlgeschlagen:\n{err}")

    # Ausgabe Zeile für Zeile auswerten
    status_by_name = {}
    for line in (out or "").splitlines():
        line = line.strip()
        if line.startswith("CREATED "):
            status_by_name[line[8:]] = "CREATED"
        elif line.startswith("EXISTS "):
            status_by_name[line[7:]] = "EXISTS"

    # DB einmalig upserten (wenn erlaubt)
    upsert_many(entries, enable_db=args.db)

    # Benutzerfreundliche Ausgabe
    for e in entries:
        name = e["name"]
        st = status_by_name.get(name)
        if st == "CREATED":
            print(f"[OK] created: {name}")
        elif st == "EXISTS":
            print(f"[SKIP] already exists: {name}")
        else:
            print(f"[?] unclear result: {name}")



def do_delete(args):
    ensure_powershell_available()

    MAX_SAFE_DELETE = 20  # >20 Treffer nur mit --all löschen

    def _q(s: str) -> str:
        return s.replace("'", "''")

    # ---------- Select rules (name/wildcard takes precedence) ----------
    if args.name:
        # Filters like in search (Default: WSL-*)
        names = [n.strip() for n in args.name.split(",") if n.strip()]
        name_list = ",".join([f"'{_q(n)}'" for n in names])
        ps_select = (
            f"$names = @({name_list}); "
            "$rules = @(); "
            "foreach ($n in $names) { "
            "  $r = Get-NetFirewallHyperVRule -Name $n -ErrorAction SilentlyContinue; "
            "  if ($r) { $rules += $r } "
            "}; "
            "$rules"
        )
    else:
        # Filter wie bei search (Default: WSL-*)
        raw_prefix = getattr(args, "prefix", None) or "WSL-*"
        prefix_pattern = raw_prefix if any(ch in raw_prefix for ch in "*?") else (raw_prefix + "*")
        filters = [f"$_.Name -like '{_q(prefix_pattern)}'"]

        if getattr(args, "name_contains", None):
            filters.append(f"$_.Name -like '*{_q(args.name_contains)}*'")

        if getattr(args, "ip", None):
            parts = [p.strip() for p in args.ip.split(",") if p.strip()]
            if parts:
                ip_or = " -or ".join([f"$_.RemoteAddresses -like '*{_q(p)}*'" for p in parts])
                filters.append(f"({ip_or})")

        if getattr(args, "protocol", None):
            protos = [p.strip().lower() for p in args.protocol.split(",") if p.strip()]
            protos = [("ICMPv4" if p == "icmp" else p.upper()) for p in protos]
            if protos:
                arr = ",".join([f"'{_q(p)}'" for p in protos])
                filters.append(f"$_.Protocol -in @({arr})")

        if getattr(args, "direction", None):
            dirs = parse_direction(args.direction)
            arr = ",".join([f"'{d}'" for d in dirs])
            filters.append(f"$_.Direction -in @({arr})")

        if getattr(args, "vmcreator_id", None):
            filters.append(f"$_.VMCreatorId -eq '{_q(args.vmcreator_id)}'")

        condition = " -and ".join(filters) if filters else "$true"
        ps_select = (
            "$rules = Get-NetFirewallHyperVRule; "
            f"$rules = $rules | Where-Object {{ {condition} }}; "
            "$rules"
        )

    # ---------- Treffer als JSON holen ----------
    ps_json = (
        f"{ps_select} | "
        "Select-Object Name,Protocol,Direction,RemoteAddresses,LocalPorts,RemotePorts,DisplayName,VMCreatorId | "
        "ConvertTo-Json -Depth 3"
    )
    code, out, err = run_ps(ps_json, dry_run=False)
    if code != 0:
        sys.exit(f"ERROR: selection failed:\n{err}")

    s = (out or "").strip()
    rules = []
    if s:
        try:
            obj = json.loads(s)
            rules = obj if isinstance(obj, list) else [obj]
        except json.JSONDecodeError:
            rules = []

    if not rules:
        print("(no matches)")
        return

    names_to_delete = [r.get("Name") for r in rules if r.get("Name")]

    # ---------- (optional) preview as a nice table ----------
    ps_table = (
        f"{ps_select} | Sort-Object Name | "
        "Format-Table Name,Protocol,Direction,RemoteAddresses,LocalPorts,RemotePorts,DisplayName,VMCreatorId -AutoSize | "
        "Out-String -Width 4096"
    )
    code2, pretty, err2 = run_ps(ps_table, dry_run=False)
    preview = (pretty or "").strip() if code2 == 0 else ""

    if args.dry_run:
        print(preview if preview else "(no matches)")
        for n in names_to_delete:
            print(f"[DRY-RUN] would delete: {n}")
        return

    # Sicherheitsgrenze (nur wenn nicht explizit --name gesetzt)
    if not args.name and len(names_to_delete) > MAX_SAFE_DELETE and not args.all:
        print(preview if preview else f"({len(names_to_delete)} matches)")
        print(f"Aborted: {len(names_to_delete)} matches. Please narrow the filter or confirm with --all.")
        return

    # ---------- Löschen ausführen ----------
    name_list_for_rm = ",".join([f"'{_q(n)}'" for n in names_to_delete])
    ps_remove = (
        f"$names = @({name_list_for_rm}); "
        "foreach ($n in $names) { "
        "  try { Remove-NetFirewallHyperVRule -Name $n -ErrorAction Stop } "
        "  catch { Write-Error $_ } "
        "}"
    )
    code3, _, err3 = run_ps(ps_remove, dry_run=False)
    if code3 != 0:
        print(f"Warning: removal returned code {code3}:\n{err3.strip()}", file=sys.stderr)

    # ---------- Update DB ----------
    if args.db and DB_FILE.exists():
        db = load_db()
        db = [e for e in db if e.get("name") not in names_to_delete]
        save_db(db)

    # ---------- Ausgabe ----------
    for n in names_to_delete:
        print(f"[OK] deleted: {n}")




def do_search(args):
    ensure_powershell_available()

    def _q(s: str) -> str:
        return s.replace("'", "''")

    # Prefix: if wildcard present -> filter directly by -Name (faster than fetching everything)
    raw_prefix = args.prefix or "WSL-*"
    use_name_param = any(ch in raw_prefix for ch in "*?")
    prefix_pattern = raw_prefix if use_name_param else (raw_prefix + "*")

    ps_parts = []
    if use_name_param:
        ps_parts.append(f"$rules = Get-NetFirewallHyperVRule -Name '{_q(prefix_pattern)}';")
    else:
        ps_parts.append("$rules = Get-NetFirewallHyperVRule;")

    # additional filters
    filters = []
    if getattr(args, "name_contains", None):
        filters.append(f"$_.Name -like '*{_q(args.name_contains)}*'")

    if getattr(args, "ip", None):
        parts = [p.strip() for p in args.ip.split(",") if p.strip()]
        if parts:
            ip_or = " -or ".join([f"$_.RemoteAddresses -like '*{_q(p)}*'" for p in parts])
            filters.append(f"({ip_or})")

    if getattr(args, "protocol", None):
        protos = [p.strip().lower() for p in args.protocol.split(",") if p.strip()]
        protos = [("ICMPv4" if p == "icmp" else p.upper()) for p in protos]
        if protos:
            arr = ",".join([f"'{_q(p)}'" for p in protos])
            filters.append(f"$_.Protocol -in @({arr})")

    if getattr(args, "direction", None):
        dirs = parse_direction(args.direction)
        arr = ",".join([f"'{d}'" for d in dirs])
        filters.append(f"$_.Direction -in @({arr})")

    if getattr(args, "vmcreator_id", None):
        filters.append(f"$_.VMCreatorId -eq '{_q(args.vmcreator_id)}'")

    if filters:
        cond = " -and ".join(filters)
        ps_parts.append(f"$rules = $rules | Where-Object {{ {cond} }};")

    # nur benötigte Felder, Ports sauber leeren, CSV ist schneller als JSON/Out-String
    ps_parts.append(
        "$rules | Select-Object "
        "Name,Protocol,Direction,RemoteAddresses,"
        "@{n='LocalPorts';e={ if($_.LocalPorts -and $_.LocalPorts -ne 'Any'){ $_.LocalPorts } else { '' } }},"
        "@{n='RemotePorts';e={ if($_.RemotePorts -and $_.RemotePorts -ne 'Any'){ $_.RemotePorts } else { '' } }},"
        "DisplayName,VMCreatorId | "
        "ConvertTo-Csv -NoTypeInformation"
    )

    ps = " ".join(ps_parts)
    code, out, err = run_ps(ps, dry_run=False)
    if code != 0:
        sys.exit(f"ERROR: search failed:\n{err}")

    # CSV -> Python-Objekte
    import csv
    from io import StringIO
    text = (out or "").strip()
    if not text:
        print("(no matches)")
        if args.db:
            save_db([])
        return

    f = StringIO(text)
    reader = csv.DictReader(f)
    rows = [dict(r) for r in reader]

    # Keep DB up to date
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    entries = []
    for d in rows:
        entries.append({
            "name": d.get("Name"),
            "displayName": d.get("DisplayName") or d.get("Name"),
            "direction": d.get("Direction"),
            "protocol": d.get("Protocol"),
            "remoteAddresses": d.get("RemoteAddresses"),
            "localPorts": (d.get("LocalPorts") or None),
            "remotePorts": (d.get("RemotePorts") or None),
            "action": "Allow",  # nicht aus CSV, aber konsistent/irrelevant für Anzeige
            "vmCreatorId": d.get("VMCreatorId"),
            "createdAt": now
        })
    if args.db:
        save_db(entries)

    # Render a nice table locally (faster than Format-Table -AutoSize)
    _render_table(rows)


def do_search2(args):
    ensure_powershell_available()

    def _q(s: str) -> str:
        return s.replace("'", "''")

    # Default: consider all WSL-* rules (including WSL-ROS2-…)
    raw_prefix = args.prefix or "WSL-*"
    # If no wildcard is present, automatically append *
    prefix_pattern = raw_prefix if any(ch in raw_prefix for ch in "*?") else (raw_prefix + "*")

    filters = [f"$_.Name -like '{_q(prefix_pattern)}'"]

    if getattr(args, "name_contains", None):
        filters.append(f"$_.Name -like '*{_q(args.name_contains)}*'")

    if getattr(args, "ip", None):
        parts = [p.strip() for p in args.ip.split(",") if p.strip()]
        if parts:
            ip_or = " -or ".join([f"$_.RemoteAddresses -like '*{_q(p)}*'" for p in parts])
            filters.append(f"({ip_or})")

    if getattr(args, "protocol", None):
        protos = [p.strip().lower() for p in args.protocol.split(",") if p.strip()]
        protos = [("ICMPv4" if p == "icmp" else p.upper()) for p in protos]
        if protos:
            arr = ",".join([f"'{_q(p)}'" for p in protos])
            filters.append(f"$_.Protocol -in @({arr})")

    if getattr(args, "direction", None):
        dirs = parse_direction(args.direction)
        arr = ",".join([f"'{d}'" for d in dirs])
        filters.append(f"$_.Direction -in @({arr})")

    if getattr(args, "vmcreator_id", None):
        filters.append(f"$_.VMCreatorId -eq '{_q(args.vmcreator_id)}'")

    condition = " -and ".join(filters) if filters else "$true"

    # Get JSON from PowerShell (instead of Format-Table) so we can update the DB
    ps = (
        "$rules = Get-NetFirewallHyperVRule; "
        f"$rules = $rules | Where-Object {{ {condition} }}; "
        "$rules | Select-Object Name,Protocol,Direction,RemoteAddresses,LocalPorts,RemotePorts,DisplayName,VMCreatorId,Action "
        "| ConvertTo-Json -Depth 3"
    )

    code, out, err = run_ps(ps, dry_run=False)
    if code != 0:
        sys.exit(f"ERROR: search failed:\n{err}")

    # PowerShell-JSON parsen (kann {} oder [] sein)
    data = []
    s = (out or "").strip()
    if s:
        try:
            obj = json.loads(s)
            data = obj if isinstance(obj, list) else [obj]
        except json.JSONDecodeError:
            data = []

    # Convert into our DB structure and save
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    entries = []
    for d in data:
        lp = d.get("LocalPorts")
        rp = d.get("RemotePorts")
        lp = None if (lp is None or str(lp).lower() in ("any", "null", "")) else str(lp)
        rp = None if (rp is None or str(rp).lower() in ("any", "null", "")) else str(rp)

        entries.append({
            "name": d.get("Name"),
            "displayName": d.get("DisplayName") or d.get("Name"),
            "direction": d.get("Direction"),
            "protocol": d.get("Protocol"),
            "remoteAddresses": d.get("RemoteAddresses"),
            "localPorts": lp,
            "remotePorts": rp,
            "action": d.get("Action") or "Unknown",
            "vmCreatorId": d.get("VMCreatorId"),
            "createdAt": now  # Zeitpunkt der Entdeckung
        })

    # Set DB to the found WSL rules (so 'list' knows current state)
    if args.db:
        save_db(entries)

    # Pretty table view via PowerShell (like before)
    ps_table = (
        "$rules = Get-NetFirewallHyperVRule; "
        f"$rules = $rules | Where-Object {{ {condition} }}; "
        "$rules | Sort-Object Name | "
        "Format-Table Name,Protocol,Direction,RemoteAddresses,LocalPorts,RemotePorts,DisplayName,VMCreatorId -AutoSize | "
        "Out-String -Width 4096"
    )
    code2, pretty, err2 = run_ps(ps_table, dry_run=False)
    if code2 == 0:
        out_txt = (pretty or "").strip()
        print(out_txt if out_txt else "(no matches)")
    else:
        # Fallback: einfache Liste (falls Format-Table fehlschlägt)
        if not entries:
            print("(no matches)")
        else:
            for e in sorted(entries, key=lambda x: x.get("name") or ""):
                lp_txt = e["localPorts"] if e["localPorts"] is not None else "-"
                rp_txt = e["remotePorts"] if e["remotePorts"] is not None else "-"
                print(f"{e['name']} | {e['protocol']} | {e['direction']} | IP={e['remoteAddresses']} | LPorts={lp_txt} | RPorts={rp_txt}")







def main():
    ap = argparse.ArgumentParser(
        description="WSL → Create/Delete Windows Hyper-V firewall rules (default prefix: WSL-ROS2). "
                    "Requires Windows administrator privileges."
    )

    # Keep only the 'examples' subcommand (no global --examples)
    # Global flags that should apply to ALL subcommands:
    global_flags = argparse.ArgumentParser(add_help=False)
    global_flags.add_argument(
        "--db", dest="db",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Enable JSON DB updates (default: off). (--no-db to disable)"
    )

    ap = argparse.ArgumentParser(
        description="WSL → Create/Delete Windows Hyper-V firewall rules (default prefix: WSL-ROS2). "
                    "Requires Windows administrator privileges.",
        parents=[global_flags],  # <— ensures --db also works BEFORE the subcommand
    )

    # Subcommands: exactly ONE add_subparsers
    sub = ap.add_subparsers(dest="action", required=True)

    # Examples subcommand
    p_examples = sub.add_parser(
        "examples", aliases=["example"], parents=[global_flags],
        help="Show example invocations"
    )

    # Common arguments for 'create'
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ip", required=True, help="Target IP(s), comma-separated, e.g. 192.168.0.213,192.168.0.214")
    common.add_argument("--protocol", default="tcp,udp,icmp",
                        help="Protocols: combination of tcp,udp,icmp (comma-separated). Default: tcp,udp,icmp")
    common.add_argument("--direction", default="both", help="in | out | both (Default: both)")
    common.add_argument("--local-ports", default=DEFAULT_LOCAL_PORTS, help="Only for TCP/UDP. Default: 0-65535")
    common.add_argument("--remote-ports", default=DEFAULT_REMOTE_PORTS, help="Only for TCP/UDP. Default: 0-65535")
    common.add_argument("--vmcreator-id", default=DEFAULT_VM_CREATOR_ID,
                        help=f"GUID for -VMCreatorId. Default: {DEFAULT_VM_CREATOR_ID}")
    common.add_argument("--prefix", default=DEFAULT_PREFIX, help=f"Rule prefix. Default: {DEFAULT_PREFIX}")
    common.add_argument("--dry-run", action="store_true", help="Show commands only, do not execute")

    # create
    p_create = sub.add_parser("create", parents=[global_flags, common], help="Create/overwrite rules")

    # delete
    p_delete = sub.add_parser("delete", parents=[global_flags], help="Delete rules (by name or filters)")
    p_delete.add_argument("--name", help="Exact name or wildcard, comma-separated (e.g. 'WSL-ROS2-TCP-IN-192.168.0.213,WSL-PI*')")
    p_delete.add_argument("--prefix", default="WSL-*", help="Name filter (Default: WSL-*)")
    p_delete.add_argument("--name-contains", help="Name contains (wildcard)")
    p_delete.add_argument("--ip", help="Filter RemoteAddresses (comma-separated)")
    p_delete.add_argument("--protocol", help="Filter protocols: tcp,udp,icmp (comma-separated)")
    p_delete.add_argument("--direction", help="Filter direction: in|out|both")
    p_delete.add_argument("--vmcreator-id", help="Filter by VMCreatorId (GUID)")
    p_delete.add_argument("--all", action="store_true", help="Delete all matches without confirmation")
    p_delete.add_argument("--dry-run", action="store_true", help="Show only, do not delete")

    # search
    p_search = sub.add_parser("search", parents=[global_flags], help="Search/show firewall rules")
    p_search.add_argument("--prefix", default="WSL-*", help="Name filter, e.g. 'WSL-*' (Default: WSL-*)")
    p_search.add_argument("--name-contains", help="Name contains (wildcard)")
    p_search.add_argument("--ip", help="Filter RemoteAddresses (comma-separated)")
    p_search.add_argument("--protocol", help="Filter protocols: tcp,udp,icmp (comma-separated)")
    p_search.add_argument("--direction", help="Filter direction: in|out|both")
    p_search.add_argument("--vmcreator-id", help="Filter by VMCreatorId (GUID)")

    args = ap.parse_args()

    if args.action in ("examples", "example"):
        print_examples()
        return
    if args.action == "create":
        do_create(args)
    elif args.action == "delete":
        do_delete(args)
    elif args.action == "search":
        do_search(args)




if __name__ == "__main__":
    main()
