# DNS Watchdog

A single-file, dependency-free Bash script that watches a machine's own network traffic for signs of **DNS poisoning / spoofing**, using `tcpdump` and POSIX `awk`. Works unmodified on both **macOS** and **Linux**.

It monitors all DNS traffic (UDP + TCP port 53) crossing the host's active interface — which on a typical single-NIC machine means both LAN and WAN traffic, since they share the same physical or virtual link — and flags packet patterns that legitimate DNS activity doesn't produce.

## What it detects

| Signal | Why it matters |
|---|---|
| **Conflicting answers to the same DNS query** | The textbook signature of a poisoning attempt: an attacker races a forged answer against the real one, hoping the forged reply arrives first and gets cached. |
| **Responses from a DNS server you never configured** | Compared against `/etc/resolv.conf` (and `scutil --dns` on macOS). A reply from an unrecognized server can indicate an off-path attacker injecting answers. |
| **Responses with no matching outstanding query** | An answer for a question the monitor never saw asked — a possible sign of injected/spoofed traffic (with a startup grace period to avoid false positives). |
| **Default gateway MAC address changes mid-session** | A background watcher polls the ARP entry for your gateway every 5 seconds. ARP spoofing is the usual first step attackers take to position themselves for on-LAN DNS tampering. |

Every alert prints two parts:

- **`[TECHNICAL]`** — raw packet detail, for anyone investigating further
- **`[WHAT THIS MEANS]`** — a plain-language explanation of why it matters

All output is also written to a timestamped log file.

## Requirements

- `tcpdump` (preinstalled on macOS; on Linux install via your package manager, e.g. `sudo apt install tcpdump`)
- `awk` (preinstalled on both macOS and Linux — no `gawk` required)
- Root privileges (raw packet capture requires it)

## Installation

```bash
git clone https://github.com/<your-username>/dns-watchdog.git
cd dns-watchdog
chmod +x dns_watchdog.sh
```

## Usage

```bash
sudo ./dns_watchdog.sh
```

By default the script auto-detects your active interface, default gateway, and configured DNS resolvers. Stop monitoring with `Ctrl+C`; a session summary prints on exit.

### Options

```
sudo ./dns_watchdog.sh [-i INTERFACE] [-o LOGFILE]
sudo ./dns_watchdog.sh -h
```

| Flag | Description |
|---|---|
| `-i INTERFACE` | Capture on a specific interface instead of the auto-detected default route |
| `-o LOGFILE` | Write the session log to a specific path (default: `./dns_watchdog_<timestamp>.log`) |
| `-h` | Show help and exit |

### Example session

```
$ sudo ./dns_watchdog.sh
=========================================================================
 DNS Watchdog — DNS poisoning / spoofing monitor
=========================================================================
Interface:         en0  (carries this host's LAN + WAN traffic)
Default gateway:   192.168.1.1  (MAC baseline: a4:5e:60:...)
Configured DNS:    1.1.1.1,8.8.8.8
Log file:          ./dns_watchdog_20260918_141200.log
...

[14:12:31.884112] [ALERT] Conflicting DNS responses for the same query
  [TECHNICAL] txn=41221  query="A? example.com. (32)"  first_response="1/0/0 A 93.184.216.34 (48)"  conflicting_response(src=10.0.0.9)="1/0/0 A 6.6.6.6 (48)"
  [WHAT THIS MEANS] Your computer asked one DNS question but got two DIFFERENT answers back for it. Legitimate DNS servers don't normally do this. This is the textbook signature of a DNS poisoning attempt, where an attacker races a forged answer against the real one, hoping the forged one arrives first and gets cached.
```

## How it works

1. `tcpdump -n -l` captures DNS traffic in real time, with hostname resolution disabled (`-n`) so output stays numeric and consistently parseable across BSD and GNU tcpdump builds.
2. A POSIX-only `awk` script (no `gawk`-specific features, so it runs as-is under macOS's built-in `awk`) tracks each DNS transaction ID: the outbound query, the first response, and every subsequent response — flagging mismatches as they occur.
3. A background loop separately polls the ARP entry for your default gateway, alerting if the MAC address behind it changes without explanation.

## Limitations

- This is a **heuristic monitor**, not a guarantee. A single isolated alert can be a false positive (e.g. a VPN switching resolvers mid-session, or a CDN returning multiple valid IPs). Repeated or clustered alerts are far more meaningful than a one-off.
- It observes traffic on the host it runs on; it cannot see poisoning that occurs purely within a remote resolver's cache before an answer ever reaches this machine.
- Requires a live interface with a default route; unusual network setups (multiple default routes, unconventional resolv.conf configurations) may need `-i` specified manually.

## License

MIT (or update to match your preference).
