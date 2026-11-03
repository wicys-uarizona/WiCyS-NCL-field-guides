# Log Analysis — NCL Field Guide

*By Ruta Rezene · University of Arizona · Women in Cybersecurity (WiCyS)*

Log analysis is "the evidence is in the lines, count and filter to the truth." You get a web/auth/app log and get asked which IP attacked, what they hit, when they got in, how many tries it took. It's mostly `grep`, `awk`, `sort`, and `uniq` used well. **Verify counts, don't eyeball them.**

---

## 1. Workflow

1. **Know the format** — which field is IP, time, method, URL, status, user-agent.
2. **Get the shape** — total lines, unique IPs, status-code spread.
3. **Filter to the anomaly** — the noisy IP, the 401 storm, the weird path.
4. **Follow the attacker's timeline** — first probe to successful hit.
5. **Answer precisely** — exact count, exact timestamp, exact IP.

**Golden rule:** let the data rank itself. `sort | uniq -c | sort -rn` tells you who and what stands out.

---

## 2. Toolbox

| Tool | Use it for |
|---|---|
| **grep** | Find lines; `-c` count, `-E` regex, `-v` exclude, `-o` only-match |
| **awk** | Pull/compute by column (`$1` is field 1) |
| **sort / uniq -c** | Rank by frequency (the core move) |
| **cut** | Slice fixed delimiters |
| **jq** | Query JSON logs |
| **wc -l** | Count lines |

Common log formats: **Apache/Nginx access** = `IP - - [time] "METHOD /path HTTP/1.1" status size "referer" "user-agent"`. **auth.log** = `time host service: message` (watch "Failed password" / "Accepted password"). **JSON** = one object per line, use `jq`.

---

## 3. The commands that answer the questions

**Top talkers (attacker IP):**
```bash
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
```

**What one IP did:**
```bash
grep "203.0.113.9" access.log
grep -c "203.0.113.9" access.log        # how many requests
```

**Status-code breakdown** (field 9 in standard combined format):
```bash
awk '{print $9}' access.log | sort | uniq -c | sort -rn
```
Then zoom: `401/403` = auth probing, `404` floods = dir brute / scanner, `500` = your injection broke something, `200` after a wall of failures = **they got in**.

**Brute force in auth.log:**
```bash
grep "Failed password" auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn   # IPs by failure count
grep "Accepted password" auth.log       # the successful login(s)
```

**Most-requested paths / find the attacked endpoint:**
```bash
awk '{print $7}' access.log | sort | uniq -c | sort -rn | head
```

**Spot injection/traversal in URLs:**
```bash
grep -Ei "union|select|<script|\.\./|/etc/passwd|%27|' or " access.log
```

**Odd user-agents (sqlmap, nikto, curl, scanners):**
```bash
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn
```

**The break-in moment:** find the attacker IP, list its requests in order, and look for the status code flipping from errors to `200` (or the `Accepted password` line). That timestamp is usually the answer.

**JSON logs:**
```bash
jq -r 'select(.status==200) | .src_ip' app.json | sort | uniq -c | sort -rn
```

---

## 4. Common pitfalls

- **Counting by eye.** Use `grep -c` / `uniq -c`. Off-by-one loses the point.
- **Wrong field number.** Verify which `$N` is status/URL for *this* log before trusting it.
- **Timezones.** Log time may not be local; answer in the format/zone asked.
- **Stopping at "many failures."** The answer is often the one success buried after them.
- **Ignoring user-agent and referer.** They out the tool and the pivot.
- **Duplicate lines** inflating counts; `sort -u` when you need distinct.

---

## 5. Quick decision tree

- **Who attacked?** `awk '{print $1}' | sort | uniq -c | sort -rn`.
- **What did they hit?** `awk '{print $7}' ...` + grep for injection patterns.
- **Did they get in?** status flips to `200`, or `Accepted password` in auth.log.
- **How many tries / requests?** `grep -c`.
- **JSON?** reach for `jq`, same ranking idea.
