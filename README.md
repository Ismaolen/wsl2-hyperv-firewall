# WSL2 Hyper-V Firewall (CLI)

<p align="center">
  <a href="assets/wsl_hyperv_firewall.gif">
    <img src="assets/wsl_hyperv_firewall.gif" alt="Demo GIF" width="720">
  </a>
</p>


Manage Windows **Hyper-V** firewall rules from **WSL**. One command to create/search/delete TCP/UDP/ICMP rules for specific IPs — no GUI, no guesswork.

> Script: `wsl_ros2_hv_firewall.py` (run inside WSL; it calls `powershell.exe` on Windows)

---

## Why this is useful (ROS / ROS 2)

If your robot is on the LAN and your nodes run in **WSL2**, Windows’ Hyper-V firewall often blocks:

* **ROS 2 DDS discovery** (multicast/broadcast over UDP)
* **ROS 1 master / services** (TCP ports like `11311`)
* Simple reachability (**ICMP/ping**)

This tool opens the right paths between **WSL ↔ Windows ↔ your robot’s IP(s)** so discovery works, topics show up, and connections stop timing out — without disabling the firewall or allowing the whole subnet.

---

## Networking note (required for ROS)

Enable WSL’s **mirrored networking** so DDS/multicast and inbound traffic reach WSL correctly:

```ini
# %UserProfile%\.wslconfig
[wsl2]
networkingMode=mirrored
```

Then restart WSL:

```bash
wsl --shutdown
```

(These rules target Hyper-V in mirrored mode and play nicely with ROS.)

---

## Features

* Create / delete / search Hyper-V firewall rules
* TCP / UDP / ICMPv4, **inbound / outbound / both**
* Multiple IPs, custom local/remote ports
* **Idempotent** (won’t duplicate)
* `--dry-run` to preview
* Optional JSON snapshot with `--db`
* Safety guard for mass deletes (override with `--all`)

---

## Requirements

* Windows 10/11 with Hyper-V (admin rights for firewall changes)
* WSL (Ubuntu etc.), Python 3
* `powershell.exe` reachable from WSL

---

## Quick start

```bash
# Help
python3 wsl_ros2_hv_firewall.py -h

# ROS/ROS2: allow all protocols IN+OUT for a robot IP (scoped to a single host)
python3 wsl_ros2_hv_firewall.py create --ip 192.168.0.213

# ROS1 (tighter): allow TCP IN for ports 11311,8080 only
python3 wsl_ros2_hv_firewall.py create \
  --ip 192.168.0.213 \
  --protocol tcp \
  --direction in \
  --local-ports 11311,8080 \
  --remote-ports 11311,8080

# Search rules (and also write a JSON snapshot)
python3 wsl_ros2_hv_firewall.py --db search

# Delete by exact/wildcard name (dry run first)
python3 wsl_ros2_hv_firewall.py delete --name 'WSL-ROS2-*' --dry-run

# More examples
python3 wsl_ros2_hv_firewall.py examples
```

---

### Notes

* **Persistence is off by default.** Add `--db` (before or after the subcommand) to write `wsl_ros2_firewall_rules.json`.
* Mass deletes are limited; pass `--all` to confirm large removals.

---

If this helped your ROS setup in WSL, a ⭐️ would be awesome.
Spotted a bug or have an idea? **Issues and PRs welcome!**

```
```
