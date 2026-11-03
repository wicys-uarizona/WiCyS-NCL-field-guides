# Network Traffic Analysis — NCL Field Guide

*By Ruta Rezene · University of Arizona · Women in Cybersecurity (WiCyS)*

Traffic analysis is "the answer is in the packets." You're handed a `.pcap`/`.pcapng` and asked who talked to whom, what they said, what file moved, or what password crossed the wire in cleartext. The whole skill is **filtering down to the one conversation that matters.**

---

## 1. Workflow

1. **Overview first** — Statistics menu, before any filter.
2. **Narrow by protocol** — HTTP? DNS? FTP? Pick the one the question implies.
3. **Follow the stream** — reassemble the full conversation.
4. **Extract** — files, credentials, the flag.
5. **Submit exactly** what you found, case and all.

**Golden rule:** start from Statistics, not from scrolling 40,000 packets. Let the summary point you.

---

## 2. Toolbox

| Tool | Use it for |
|---|---|
| **Wireshark** | GUI analysis: filters, Follow Stream, export objects |
| **tshark** | Wireshark on the command line, scriptable |
| **NetworkMiner** | Auto-carves files, images, creds, sessions from a pcap |
| **tcpdump** | Quick capture/read, filter on headless boxes |
| **Scapy** | Craft/parse packets when you need custom logic |

---

## 3. Wireshark moves that solve most challenges

**Orient yourself (Statistics menu):**
- **Protocol Hierarchy** — what's actually in the capture.
- **Conversations** — top talkers by bytes; the busy pair is usually the point.
- **Endpoints** — every host.

**Follow a stream:** right-click a packet → Follow → TCP/HTTP/UDP Stream. This reassembles both sides into readable text. This is where cleartext creds and flags live.

**Export files:** File → Export Objects → HTTP (or SMB, TFTP, IMF). Pulls transferred files straight out.

**Display filters** (type in the bar, these are display, not capture, filters):
```
http.request                       ip.addr == 10.0.0.5
http.request.method == "POST"      tcp.port == 21
dns.qry.name contains "flag"       tcp contains "password"
ftp                                frame contains "SKY-"
tcp.flags.syn == 1 && tcp.flags.ack == 0    # connection attempts
http.response.code == 200
```
Combine with `&&`, `||`, `!`. `contains` searches bytes; `matches` takes regex.

**Cleartext credentials** ride on: FTP (21), Telnet (23), HTTP Basic auth, POP3/IMAP/SMTP. Filter the protocol, Follow Stream, read the `USER`/`PASS`. HTTP Basic auth is base64 in the `Authorization:` header, decode it.

**DNS tricks:** data exfil and C2 hide in long/odd subdomains. `dns.qry.name` and look for base64-ish or hex labels.

**HTTPS/TLS:** encrypted by default. Only readable if the challenge supplies a key log file: Preferences → Protocols → TLS → (Pre)-Master-Secret log filename.

**tshark one-liners:**
```bash
tshark -r cap.pcap -Y "http.request" -T fields -e http.host -e http.request.uri
tshark -r cap.pcap -Y "ftp" -T fields -e ftp.request.command -e ftp.request.arg
tshark -r cap.pcap --export-objects http,./out    # dump transferred files
```

---

## 4. Common pitfalls

- **Scrolling instead of filtering.** Statistics → Conversations first, every time.
- **Capture filter vs display filter.** You want *display* filters (the bar inside Wireshark).
- **Missing the second half.** Follow Stream shows both directions; a lone packet doesn't.
- **Expecting to read TLS.** No key log = no plaintext. Say so and move on.
- **Overlooking DNS/ICMP** as exfil channels when HTTP looks empty.
- **Retyping the flag.** Copy it out of the stream; don't transcribe.

---

## 5. Quick decision tree

- **Where's the action?** Statistics → Protocol Hierarchy + Conversations.
- **Credentials?** Filter `ftp`/`telnet`/`http`, Follow Stream, read USER/PASS.
- **A file moved?** Export Objects, or `--export-objects` in tshark.
- **Weird DNS?** `dns.qry.name` for long/encoded labels.
- **Looking for a known flag?** `frame contains "SKY-"`.
