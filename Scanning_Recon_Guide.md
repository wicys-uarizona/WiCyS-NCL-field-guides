# Scanning & Reconnaissance — NCL Field Guide

*By Ruta Rezene · University of Arizona · Women in Cybersecurity (WiCyS)*

Scanning & Recon is "map the target, then read the map." You're pointed at a host (or handed scan output / an nmap file) and asked what's open, what's running, what version, what the service is leaking. **Only scan targets the challenge gives you.** Scanning anything else is illegal.

---

## 1. Workflow

1. **Host discovery** — is it up, what's the IP.
2. **Port scan** — which ports are open.
3. **Service + version** — what's listening, which version (`-sV`).
4. **Enumerate** the interesting services (banners, scripts, default creds).
5. **Answer the exact ask** — a port, a version string, a service, a banner value.

**Golden rule:** read the whole scan before chasing one port. The answer is often the odd service, not the obvious one.

---

## 2. Toolbox

| Tool | Use it for |
|---|---|
| **nmap** | The workhorse: ports, versions, OS, NSE scripts |
| **masscan** | Very fast first sweep of huge port ranges |
| **netcat (nc)** | Manual banner grab, raw connect |
| **whatweb / httpx** | Identify web stacks and headers |
| **nikto / gobuster** | Web server + path enumeration (see Web guide) |
| **enum4linux-ng** | SMB/NetBIOS shares, users, OS |
| **snmpwalk** | SNMP (udp 161) — often wide open with `public` |

---

## 3. Nmap, the parts you actually use

```bash
nmap -sV -sC -p- 10.10.10.5           # all 65535 ports, versions, default scripts
nmap -sV --top-ports 1000 target       # faster: common ports only
nmap -sU --top-ports 50 target         # UDP (DNS 53, SNMP 161, etc.) — slow, do separately
nmap -A target                         # aggressive: -sV -sC -O + traceroute
nmap -p 80,443 --script http-title,http-headers target
nmap -oN out.txt / -oG grep.txt / -oA all   # save output (do this)
```

**Flag cheat:**
- `-sS` SYN scan (default as root) · `-sT` TCP connect (no root) · `-sU` UDP
- `-sV` version detection · `-sC` default NSE scripts · `-O` OS detection
- `-p-` all ports · `-p 22,80` specific · `--top-ports N` most common
- `-Pn` skip host discovery (target "down" but you know it's up) · `-T4` faster timing
- `-A` everything at once

**Port states:** `open` (listening), `closed` (reachable, nothing there), `filtered` (firewall dropped it, no reply). "Filtered" ≠ closed.

**Banner grab by hand** when `-sV` is vague:
```bash
nc -nv target 22        # SSH/FTP/SMTP announce themselves on connect
printf 'HEAD / HTTP/1.0\r\n\r\n' | nc target 80
```

**Common ports to recognize on sight:** 21 FTP · 22 SSH · 23 Telnet · 25 SMTP · 53 DNS · 80/443 HTTP(S) · 110 POP3 · 139/445 SMB · 143 IMAP · 161 SNMP · 3306 MySQL · 3389 RDP · 5432 Postgres · 8080 HTTP-alt.

**NSE scripts** live in `/usr/share/nmap/scripts/`. Useful categories: `--script vuln`, `--script http-enum`, `--script smb-enum-shares`, `--script ssl-cert` (cert pulls names/dates).

---

## 4. Reading given scan output

If the challenge hands you an `.nmap`/`.gnmap`/`.xml` file instead of a live host:
```bash
grep -i open scan.gnmap               # quick port list
grep "Nmap scan report" scan.nmap     # hosts
```
For XML, `xsltproc scan.xml -o scan.html` makes it readable, or open in a browser.

---

## 5. Common pitfalls

- **Forgetting `-p-`.** Default nmap scans ~1000 ports; the flag service is often on a high port.
- **Skipping UDP.** DNS/SNMP/TFTP answers hide there. Run a small `-sU` pass.
- **Taking "filtered" as closed.** Try `-Pn`, try again, note the firewall.
- **Not saving output** (`-oA`). You'll re-run slow scans for data you already had.
- **Trusting the port number over `-sV`.** Services get moved; verify what's actually there.
- **Ignoring SNMP/SMB.** `public` SNMP and anonymous SMB leak tons for free.

---

## 6. Quick decision tree

- **Live host?** `nmap -sV -sC -p- target`, save with `-oA`.
- **Version/banner wanted?** `-sV`, confirm with `nc`.
- **Web port open?** whatweb + gobuster (hand to Web guide).
- **445/139 open?** enum4linux-ng. **161/udp?** snmpwalk with `public`.
- **Given a scan file?** grep for `open`, read every service, not just port 80.
