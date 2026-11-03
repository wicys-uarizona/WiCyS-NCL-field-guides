# Password Cracking — NCL Field Guide

*By Humza Sheikh · University of Arizona · Women in Cybersecurity (WiCyS)*

A full, general-use reference for the NCL **Password Cracking** category and CTFs in general. You're handed hashes, or hash-protected files, and you recover the plaintext. All of this is legal on challenge-provided material you're authorized to attack — **never** run it against accounts, systems, or files you don't own or aren't explicitly cleared to test. Mode numbers below are verified against the official hashcat example-hashes list; always confirm on your own build with `hashcat --example-hashes`, since numbers can shift between releases. Again this is for CTF use ONLY and misuse of any kind WiCyS UA chapter does not condone or support of illegal acts! 

---

## 1. The workflow (it's always the same five steps)

1. **Identify** the hash type (length, prefix, where it came from).
2. **Choose** the tool and the hashcat `-m` mode (or let John auto-detect).
3. **Attack** cheaply first: wordlist → wordlist + rules → mask/hybrid.
4. **Read** the output and pair each hash back to its plaintext.
5. **Escalate** only on what's left (bigger list, heavier rules, targeted masks).

**Golden rule:** run the cheap attacks across *all* the hashes before you sink an hour into brute-forcing one. Most CTF passwords fall to `rockyou + best64`. What these are just password data dumps. Of old leaked real passwords that are compiled. 

> Quick note! dont stress memorizing all this. Think of it like a recipe, you follow the same 5 steps top to bottom every time and it just becomes muscle memory after a couple challenges. You got this :)

---

## 2. Core toolbox (what each tool is, and where to get it)

| Tool | Use it for | Notes |
|---|---|---|
| **hashcat** | GPU cracking of everything | Fastest. Attack type = `-a`, hash type = `-m`|
| **John the Ripper (Jumbo)** | CPU cracking + the `*2john` converters | Auto-detects many formats; the jumbo build ships ~100 `*2john` extractors. |
| **hashid** / **hash-identifier** | Naming an unknown hash | `hashid 'HASH'` prints candidate hashcat modes. |
| **CyberChef** | Sanity checks | Hash a guessed plaintext and compare; decode layered encodings. |
| **CrackStation** / online rainbow lookups | Instant hits on common **unsalted** hashes | First try for MD5/SHA1/NTLM. Useless on salted or rare hashes. |
| **Name-That-Hash** (`nth`) | Modern alternative to hashid | More detail, ranks likelihood. |

**The `*2john` family** turns a protected file into a crackable hash line:
`zip2john`, `rar2john`, `7z2john`, `office2john`, `pdf2john`, `ssh2john`, `keepass2john`, `bitlocker2john`, plus dozens more.
Example: `office2john report.docx > hash.txt`, then crack `hash.txt`. On Kali they live in `/usr/share/john/` or just on your `$PATH`. If this doesnt make sense Dont worry these are just commands exmaple of a tool called john the ripper. Question with full solutions down below.

> *Real talk, if the command line looks scary right now thats completely normal, every single person started there. You're not supposed to know these commands yet, you learn them by typing them and breaking stuff. Copy, run, see what happens, repeat.*

### Where to get these tools (download & docs)

On Kali Linux most of these are already installed. Everywhere else, grab them here:

**Core tools**
- **hashcat** — https://hashcat.net/hashcat/
- **hashcat example-hashes** (a sample hash for every `-m` mode — great for IDing a hash) — https://hashcat.net/wiki/doku.php?id=example_hashes
- **John the Ripper (Jumbo)** — https://www.openwall.com/john/ (source + all the `*2john` converters)
- **hcxtools** (turns a Wi-Fi capture into a hashcat `22000` line) — https://github.com/ZerBea/hcxtools

**Online hash tools — in your browser, no install**
- **CrackStation** — instant lookup of common *unsalted* MD5/SHA1/NTLM — https://crackstation.net/
- **CyberChef** — hash, decode, and compare anything — https://gchq.github.io/CyberChef/
- **Name-That-Hash** — identify an unknown hash — web https://nth.skerritt.blog/ · repo https://github.com/HashPals/Name-That-Hash
- **hashes.com** — hash identifier + community lookups — https://hashes.com/en/tools/hash_identifier
- **Online lookups **upload your hash to a third party** — use them for CTF/practice hashes only, never real-engagement data (§11, item 6).

**Wordlists & rules**
- **rockyou.txt** — the default wordlist (on Kali at `/usr/share/wordlists/rockyou.txt.gz` — `gunzip` it once)
- **SecLists** — the standard collection of wordlists — https://github.com/danielmiessler/SecLists
- **weakpass** — large downloadable password lists — https://weakpass.com/
- **hashcat built-in rules** (best64, dive, leetspeak, toggles…) — https://github.com/hashcat/hashcat/tree/master/rules
- **OneRuleToRuleThemStill** — the maintained successor to OneRuleToRuleThemAll — https://github.com/stealthsploit/OneRuleToRuleThemStill

---

## 3. Identify the hash

Check length and charset first, then confirm the source (Windows? Linux shadow? a file?).

> *New to this? All you're doing here is matching the LOOK of your hash to a row in the table, thats it. Count the characters (32? 40? 64?) or check what it starts with (`$6$`, `$2y$` etc) and read across for the `-m` number. Thats the whole game.*

| Looks like | Length / prefix | Likely type | hashcat `-m` |
|---|---|---|---|
| hex | 32 | **MD5** or **NTLM** | 0 or 1000 |
| hex | 40 | SHA1 | 100 |
| hex | 64 | SHA-256 | 1400 |
| hex | 128 | SHA-512 | 1700 |
| `$1$…` | — | md5crypt | 500 |
| `$5$…` | — | sha256crypt | 7400 |
| `$6$…` | — | sha512crypt (Linux `/etc/shadow`) | 1800 |
| `$2a$`/`$2b$`/`$2y$…` | ~60 | bcrypt | 3200 |
| `$y$…` / `$7$…` | — | yescrypt / scrypt | check `--help` |
| `user:RID:LM:NTLM:::` | — | NTLM dump (crack the NTLM half) | 1000 |

**The #1 trap: MD5 vs NTLM.** Both are 32 hex chars. If it came from Windows (SAM, NTDS.dit, a `user:RID:LM:NTLM` line), it's **NTLM `-m 1000`**. Otherwise try **MD5 `-m 0`**.

When stuck: `hashcat --example-hashes | less` shows a sample hash for every mode — match the shape of yours.

---

## 4. File / artifact hash modes (verified from hashcat wiki)

These are the ones CTFs love — a locked file you must convert, then crack: (Also a tip try reading the documentation of tools when you can to get a better grasp or a quick 10 mins youtube video!)

> *This one trips people up so let me say it plain. A locked file (zip, pdf, word doc) has a little password-check hidden inside it, and the `2john` tools just pull that check OUT as a hash so you can crack it like any other. You're not "breaking the file", you're just cracking its password.*

| Format | Converter | hashcat `-m` |
|---|---|---|
| ZIP (PKZIP, legacy) | `zip2john` | 17200 (compressed), 17210/17220 (variants) |
| ZIP (WinZip AES) | `zip2john` | 13600 |
| RAR3 | `rar2john` | 12500 |
| RAR5 | `rar2john` | 13000 |
| 7-Zip | `7z2john` | 11600 |
| MS Office 2007 / 2010 / 2013 | `office2john` | 9400 / 9500 / 9600 |
| PDF 1.1–1.3 (Acrobat 2–4) | `pdf2john` | 10400 |
| PDF 1.4–1.6 | `pdf2john` | 10500 |
| PDF 1.7 (L3 / L8) | `pdf2john` | 10600 / 10700 |
| KeePass | `keepass2john` | 13400 |
| SSH private key | `ssh2john` | 22911 / 22921 / 22931 (by cipher) |
| WPA/WPA2 handshake or PMKID | `hcxpcapngtool` | 22000 |

---

## 5. Attack modes (hashcat `-a`) Better on more powerful gpu's etc. 

> *Heads up, here's the thing people mix up most. `-m` is WHAT the hash is and `-a` is HOW you attack it. `-m` means hash type, `-a` means attack style. Keep those two straight and half your errors disappear.*

- **`-a 0` Straight (wordlist)** — try every word. Always start here.
  `hashcat -m 0 hash.txt rockyou.txt`
- **`-a 0` + rules** — mutate each word (append digits, capitalize, leetspeak). Biggest bang for human passwords.
  `hashcat -m 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule`
- **`-a 3` Mask (brute force)** — try a known pattern.
  `hashcat -m 0 hash.txt -a 3 '?u?l?l?l?l?l?d?d'`
- **`-a 6` Hybrid (word + mask)** — `rockyou` words with `?d?d?d` appended.
  `hashcat -m 0 hash.txt -a 6 rockyou.txt '?d?d?d'`
- **`-a 7` Hybrid (mask + word)** — digits/symbols *before* each word.
- **`-a 1` Combinator** — join two wordlists (`word1word2`).

**Mask charsets:** `?l`=a-z · `?u`=A-Z · `?d`=0-9 · `?s`=symbols · `?a`=all printable · `?b`=all bytes.
**Custom sets:** `-1 ?l?d` defines `?1` = lowercase + digits, then use `?1` in the mask. Up to 4 custom sets (`-1`…`-4`).
**Increment:** `-a 3 --increment ?a?a?a?a?a?a` tries lengths 1→6 in turn.

---

## 6. Wordlists & rules

> *rockyou is honestly just a giant text file of real passwords that leaked years ago, no magic to it. You point hashcat at it and it tries each one super fast, thats all a "dictionary attack" really is.*

**Wordlists**
- **rockyou.txt** — the default. Kali: `/usr/share/wordlists/rockyou.txt.gz` → `sudo gunzip` it once. ~14M real leaked passwords; cracks most easy/medium challenges.
- **SecLists** — `apt install seclists` → `/usr/share/seclists/Passwords/…`. Themed and probable-password lists.
- **Custom list from the prompt** — NCL themes passwords around the scenario (names, places, dates, org words). Pull those words from the challenge text and feed them in; this is how you crack the "hard" ones generic lists miss.
- **Mangle a small list** into a big one with rules (below) instead of downloading huge files.

**Rules (word mutators)**
- **`best64.rule`** — 64 rules, statistically the most effective per rule. Roughly ~45% hit rate for ~3× the work (a *rough* community figure, not a guarantee — see §11, item 9). **Run this first.**
- **`OneRuleToRuleThemAll`** — ~52,000 rules, a *rough* ~78% hit rate but ~900× the work. Run after best64 for thorough coverage.
- **`dive.rule`** / **`rockyou-30000.rule`** — heavier built-ins that ship with hashcat.
- Rule files live in `/usr/share/hashcat/rules/`. Stack efficiency: start small, escalate only on uncracked hashes.

---

## 7. Reading & submitting results

> *Heads up, this is the one that'll make you wanna toss your laptop lol, you crack it, you submit, and it says WRONG. 9 times out of 10 its a capital letter, a sneaky space, or a `$HEX` thing (see §11). Copy the answer exactly, never retype it from memory.*

- Cracked pairs print live and are saved to `~/.local/share/hashcat/hashcat.potfile`.
- **Re-show paired results (critical for multi-hash questions):** `hashcat -m 0 hash.txt --show` — prints `hash:plaintext` in file order. hashcat cracks in *speed* order, not file order, so always use `--show` to map answers correctly.
- `--username` handles `user:hash` lines and keeps the mapping.
- If a hash seems "uncrackable," it may already be in your potfile from a past run — `--show` reveals it, or `--potfile-disable` to force a clean re-run.
- **Submit exactly** what you cracked. NCL checks are literal — watch case, symbols, and trailing characters.

---

## 8. GPU / performance (your rig)

- **Crack on the host OS, not inside a VM.** VMs don't get GPU passthrough, so hashcat drops to slow CPU.
- Benchmark a mode: `hashcat -b -m 0`.
- "No devices found / left" → install the GPU runtime (NVIDIA driver + CUDA). Test with `-D 1` (force CPU) or `--force`.
- **Match effort to hash speed:**
  - **Fast** (MD5/NTLM/SHA1): billions/sec → masks and brute force are viable.
  - **Slow** (bcrypt, sha512crypt `$6$`, yescrypt, Office/PDF/KeePass): hundreds–thousands/sec → **wordlist + rules only**; brute force will time out.
- Use `--status --status-timer=10` to watch progress; `-O` (optimized kernel) speeds things up but caps password length (~31 chars) — fine for most CTFs, where passwords are short, but drop it if a long passphrase is plausible (see §11, item 7).

---

## 9. Common pitfalls (where points die)

- **Wrong `-m` mode** → "No hashes loaded" or instant "Exhausted." Re-identify.
- **MD5 vs NTLM** mix-up (see §3) — the single most common miss.
- **Trailing newline / whitespace** in the hash file → silent fail. Strip it.
- **Salted hash pasted into CrackStation** — online tables only cover unsalted hashes.
- **Brute-forcing a slow hash** — you'll run out of competition time. See §8.
- **Reading multi-hash output in crack order** instead of `--show` order → mismatched answers.
- **Ignoring the scenario** — themed wordlists beat generic ones on the hard challenges.
- **Forgetting the potfile** — a "stuck" hash may already be solved from earlier; `--show`.
- **Case / exact-format on submit** — the checker is literal.
- **Cracking in a VM** and blaming hashcat for being slow — move to the host.

---

## 10. Copy/paste starters

```bash
# 1) identify
hashid 'HASH_HERE'               # or: nth -t 'HASH_HERE'

# 2) wordlist (always first)
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt

# 3) wordlist + best64 rules (the money move)
hashcat -m 0 hash.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# 4) mask: capital + 5 lower + 2 digits  (e.g. Summer22)
hashcat -m 0 hash.txt -a 3 '?u?l?l?l?l?l?d?d'

# 5) hybrid: rockyou word + 3 digits
hashcat -m 0 hash.txt -a 6 rockyou.txt '?d?d?d'

# 6) protected file  ->  hash  ->  crack
office2john report.docx > hash.txt     # or zip2john / pdf2john / ssh2john / keepass2john
hashcat -m 9600 hash.txt rockyou.txt   # pick -m to match the file type (see §4)

# 7) show cracked pairs in file order
hashcat -m 0 hash.txt --show

# 8) John the Ripper (CPU, auto-detect, great for files)
john --wordlist=rockyou.txt --rules hash.txt
john --show hash.txt
```

---

## 11. Adversarial scan — where this guide (and you) still lose points

These are the traps that make a password you *did* crack score zero, or make a crackable hash look impossible. Each one is written the same way: **what you'll see**, **why it happens**, and **the fix**.

> *Heads up, this section is the "you've cracked a few, now level up" stuff. If you're brand new, skim it once and come back after a couple challenges, itll click way faster then.*

---

**1. The `$HEX[...]` trap — "I cracked it but it's marked wrong."**

- **What you'll see:** your answer prints as `...:$HEX[70617373203132]` instead of a normal word, and the NCL checker rejects it.
- **Why:** when a password has a space or an unusual character in it, hashcat can't display it safely, so it shows the *hex code* for the letters instead. `$HEX[...]` is a coded version of the password, not the password.
- **Fix:** translate the hex back into text — `echo 70617373203132 | xxd -r -p` → `pass 12`. Submit the decoded text (`pass 12`), not the `$HEX[...]` string.

---

**2. Windows line endings & the BOM (this bites you specifically — you're on Windows).**

- **What you'll see:** "No hashes loaded," "Separator unmatched," or a hash that never cracks — right after you made the hash file in Notepad or PowerShell.
- **Why:** Windows quietly adds invisible characters to text files: a carriage return (`\r`) at the end of every line, and sometimes a marker called a BOM (byte-order mark) at the very start. hashcat reads those invisible bytes as *part of the hash*, so it no longer matches anything.
- **Fix:** save the file with "LF" line endings and "UTF-8 without BOM" (in VS Code, click the encoding and the `CRLF`/`LF` buttons in the bottom status bar), or run `dos2unix hash.txt`. To check for the hidden bytes: `xxd hash.txt | tail` — a `0d` at the end of a line is a stray `\r`; `ef bb bf` at the very start is a BOM.

---

**3. `hashid` guesses, and it guesses wrong a lot.**

- **What you'll see:** `hashid` prints a long list of "possible" hash types, you pick the top one, and nothing cracks.
- **Why:** `hashid` only looks at the length and characters of the hash, but many different hash types look identical — every 32-character hex string looks like MD5 *and* NTLM *and* several others. Its first guess is often not the right one.
- **Fix:** decide from **where the hash came from** first — a Windows computer points to NTLM (`-m 1000`); a website's user database is usually MD5 (`-m 0`). Confirm by running `hashcat -m <mode> --example-hashes`, which prints a sample of that type so you can compare the shape. Use Name-That-Hash as a second opinion.

---

**4. The "LM" hash in a Windows dump is free points — don't skip it!!!!!!!**

- **What you'll see:** a Windows dump line like `jsmith:1001:aad3b435...:8846f7ea...:::` and you go straight for the long fourth field — the slow way.
- **Why:** that line actually holds **two** password hashes. The third field is the LM hash (hashcat mode **3000**) — an old, weak format that ignores capitalization and only handles 7 characters at a time, so it cracks almost instantly. The fourth field is the stronger NTLM hash (mode **1000**).
- **Fix:** crack the LM hash first — it hands you the password in ALL CAPS. Then crack NTLM using that word as a tiny one-line wordlist with a "toggle case" rule (`rules/toggles*.rule`) to find the real capitalization. You get the answer in a fraction of the time.

---

**5. Let the converter tell you the mode — don't guess it.**

- **What you'll see:** you run `zip2john`/`office2john`, type a mode number you remembered, and get "No hashes loaded."
- **Why:** the converter prints the exact type at the start of its output (a tag like `$zip2$` or `$office$*2013*`), and one file format can map to several modes — a ZIP might be `17200` or `13600`, and Office is `9400`/`9500`/`9600` depending on the year. Guessing instead of reading the tag picks the wrong number.
- **Fix:** read the tag the converter actually produced and match the mode to it: `$office$*2013*` → `-m 9600`; `$zip2$` → `-m 13600`; and so on. The hashcat example-hashes page lists every tag and its mode.

---

**6. Online crackers quietly hand your hash to a stranger.**

- **What you'll see:** nothing goes wrong in a CTF — but a risky habit is forming for real work.
- **Why:** sites like CrackStation work by you *uploading* the hash to their servers. That's harmless for a practice hash everyone already has. For a real job, that hash can represent a real person's password, and you've just given it to someone else's website.
- **Fix:** use online crackers only for CTF/practice hashes. Never paste a hash tied to a real client, system, or account — crack those on your own machine with hashcat or John.

---

**7. `-O` can skip the answer without telling you.**

- **What you'll see:** you add `-O` to run faster, the attack finishes "Exhausted," and you conclude the password can't be cracked — but it actually could.
- **Why:** `-O` ("optimized mode") goes faster by only trying passwords up to a certain length (often 31 characters, sometimes fewer). Anything longer is silently never tested.
- **Fix:** if the password might be a long phrase (like `correct horse battery staple`), leave `-O` off. Only use it when you're confident the password is short — which, for most CTF challenges, it is.

---

**8. The potfile remembers old cracks — usually helpful, sometimes misleading.**

- **What you'll see:** a hash you expected to take a while cracks "instantly," or re-running an attack to demo it looks faster than it really was.
- **Why:** hashcat saves every password it has ever cracked into a file called the *potfile* and reuses it. So a "crack" might just be a memory of an earlier run, not fresh work.
- **Fix:** that memory is mostly a good thing — `hashcat … --show` uses it to re-display answers you already found (great for mapping multi-hash questions). But when you want honest timing (a benchmark or a demo), add `--potfile-disable` to force a clean run.

---

**9. Those rule "hit rate" percentages are rough folklore, not promises.**

- **What you'll see:** guides claiming "best64 = 45%, OneRuleToRuleThemAll = 78%," and you expecting those exact results on your challenge.
- **Why:** those numbers came from testing against one specific leaked password set. Your challenge's passwords are different, so the percentages won't carry over.
- **Fix:** treat them as rough guidance only: `best64` is small and cheap, so run it early on everything; `OneRuleToRuleThemAll` is huge and slow, so save it for the few hashes nothing else cracked.

---

**10. Do the brute-force math *before* you start, or you'll waste your whole time budget.**

- **What you'll see:** you launch a brute-force mask, the time estimate reads "4 years," and you've burned a move.
- **Why:** brute force tries every possible combination, and the count explodes fast. 8 fully-random characters is 95⁸ ≈ 6.6 *quadrillion* guesses. Even at 50 billion guesses per second that's about 37 hours — and on a slow hash like bcrypt, effectively forever.
- **Fix:** estimate first: *(number of possible characters) raised to the (length), divided by your speed.* Get your speed from `hashcat -b -m <mode>`. If the result is longer than the time you have, don't brute force — use a wordlist, rules, or a mask that only brute-forces the part you don't know (like Problem 3).

---

## 12. Practice problems (easy → final boss), with full solutions

New here? A quick vocabulary before you start:
- **Hash** = the scrambled version of a password. **Plaintext** = the real password you're trying to recover.
- **Wordlist** = a big text file of password guesses (the famous one is `rockyou.txt`, ~14 million real leaked passwords).
- **Rules** = automatic tweaks hashcat makes to each guessed word (add numbers, capitalize, swap letters).
- **Mask** = a pattern you brute-force when you know the *shape* of a password but not the characters.
- **`-m`** picks the hash type; **`-a`** picks the attack style. `--show` prints each hash next to the password you cracked.

Each solution below is laid out the same way: **the challenge → a step-by-step walkthrough (plain words, then the command) → the answer → the lesson and what to watch out for.** Put the hashes for each problem in a text file (one per line) before you run the commands.

The MD5/SHA hashes below are **real** — check any of them yourself with `echo -n sunshine | md5sum` or by pasting into CyberChef. Problem 4's file hash is a labeled *sample* with a do-it-yourself recipe, because a real file hash is unique to your own machine. Save hash files with **LF** line endings (see §11, item 2 — this matters on Windows). Passwords are themed the way NCL themes them (`SKY-` flags, mascots, founding years, leetspeak), so these also drill the "pull words from the scenario" habit.

> *You don't have to finish all of them in one sitting. Do Problem 1, feel the win, then come back. Thats genuinely the best way to learn this.*

### Problem 1 — "Straight to the point" *(Easy)*

**The challenge:** someone leaked three MD5 password hashes from a fan forum. Recover the three real passwords.
```
0571749e2ac330a7455809c6b0e7af90
bec92397646e8feb93667ae2e6bc931b
1fc3a78289477bb2cf4410449c07c7a0
```
**Walkthrough**
1. **Figure out the hash type.** Each is 32 hex characters (0–9, a–f) and it came from a website database, so it's **MD5** → mode `-m 0`. (A 32-hex hash *could* be NTLM, but that comes from Windows, and a forum isn't Windows.)
2. **Try the laziest thing first.** Paste each hash into **CrackStation** (a free site that looks up common unscrambled hashes). For passwords this ordinary, you get instant answers.
3. **Or crack it locally.** Put the three hashes in `p1.txt` (one per line), then:
   ```bash
   hashcat -m 0 p1.txt /usr/share/wordlists/rockyou.txt   # try every word in the rockyou list
   hashcat -m 0 p1.txt --show                              # print each hash next to its password
   ```
4. **Answers:** `sunshine` · `letmein1` · `wildcats`

**The lesson:** run the cheapest attack (a plain wordlist) across *every* hash before trying anything fancier. **Watch out for:** reaching for masks or rules here — all three were plain wordlist words, so that would only waste time (§1 golden rule).

### Problem 1B — "Known flag shape" *(Easy — modeled on the NCL gym "Mask" challenge)*

**The challenge:** three MD5 hashes whose passwords all follow one fixed shape — `SKY-HQNT-` then **4 digits**. (This is the real gym "Mask" challenge format; only the four digits change.)
```
fdbebaaecbbd2b7872b96a739fd9bd5c
e477205b6597c8ede359d274c96e7070
b19d0bf7ed9000c7953bcd91173e2320
```
**Walkthrough**
1. **Hash type:** 32 hex → **MD5** → mode `-m 0`.
2. **Don't bother with a wordlist** — you already know the whole password except the 4 digits. Brute-force *only those* with a mask (`-a 3`), where `?d` = one digit:
   ```bash
   hashcat -m 0 p1b.txt -a 3 'SKY-HQNT-?d?d?d?d'
   ```
   That's just 10 × 10 × 10 × 10 = **10,000** guesses — done the instant you hit Enter. Quote the mask so the shell leaves the `?` alone.
3. **Map the answers:** `hashcat -m 0 p1b.txt --show`
4. **Answers:** `SKY-HQNT-7420` · `SKY-HQNT-0096` · `SKY-HQNT-3185`

**The lesson:** when the format is fixed and only a few characters vary, a mask beats a wordlist every time — the keyspace is tiny. **Watch out for:** dropping the quotes around the mask (the shell may mangle `?`), and reading `--show` order rather than console order so each flag maps to the right hash. (Problem 3 is the harder version of this — same idea, but the unknown characters are letters *and* digits.)

### Problem 2 — "Spirit week" *(Hard)*

**The challenge:** one SHA-1 hash. A plain rockyou run won't crack it.
```
87bcaae14e1db759100430dbfa51c9d152c2ba64
```
**Walkthrough**
1. **Hash type:** 40 hex characters → **SHA-1** → mode `-m 100`.
2. **Plain wordlist — fails.**
   ```bash
   hashcat -m 100 p2.txt rockyou.txt
   ```
   It finishes and says **"Exhausted"** (hashcat tried the whole list and found nothing). So the password isn't in rockyou as-is.
3. **Wordlist + rules — still fails.** Rules are automatic tweaks to each word; `best64` is a small, popular set of 64 of them:
   ```bash
   hashcat -m 100 p2.txt rockyou.txt -r rules/best64.rule
   ```
   Still nothing — so the *base word itself* isn't in rockyou.
4. **Use the scenario.** "Spirit week" points to a school/mascot password. Make your own small list, `themed.txt`, and include a Capitalized form (the capital letter will matter):
   ```
   wildcat
   Wildcat
   arizona
   beardown
   tucson
   ```
5. **Guess the shape.** These passwords are often `Word + year + symbol`. A **hybrid attack** glues a word to a pattern: `-a 6` means "wordlist first, then a pattern on the end," `?d` is one digit, and `!` is a literal `!`:
   ```bash
   hashcat -m 100 p2.txt -a 6 themed.txt '?d?d?d?d!'
   ```
   This tries each word + four digits + `!`, e.g. `Wildcat` + `2026` + `!`.
6. **Read the result:** `hashcat -m 100 p2.txt --show`
7. **Answer:** `Wildcat2026!`

**Why it's hard:** you had to realize the word wasn't in any stock list, build your own from the theme, and spot the "Capital + year + symbol" shape to choose the hybrid pattern. **Watch out for:** leaving out the capitalized `Wildcat` — then the pattern never matches the real password.

### Problem 3 — "Flag format leaked" *(Hard)*

**The challenge:** one SHA-256 hash. A tip says the answer looks like `SKY-` followed by **4 characters that are uppercase letters or digits**.
```
b3a48c84ec38f620358248c78a3986355355a0b99703a595d5e7a716b4c0d844
```
**Walkthrough**
1. **Hash type:** 64 hex characters → **SHA-256** → mode `-m 1400`.
2. **Don't use a wordlist** — the answer is a random-looking code, not a word. But you *know its shape*, so you brute-force only the unknown part. That's a **mask attack**, `-a 3`.
3. **Build the mask.** A mask describes the password one position at a time: `?u` = any uppercase letter, `?d` = any digit. You can bundle them into your own set with `-1`, then reuse it as `?1`:
   ```bash
   hashcat -m 1400 p3.txt -a 3 -1 ?u?d 'SKY-?1?1?1?1'
   ```
   `-1 ?u?d` means "`?1` stands for A–Z plus 0–9," so this tries `SKY-` then every 4-character mix of letters and digits. That's only 36 × 36 × 36 × 36 = **1,679,616** guesses — instant for SHA-256 on your GPU.
4. **Answer (`--show`):** `SKY-K9Q2`

**Why it's hard:** the trick is brute-forcing *only the 4 unknown characters* instead of the whole string, and building the right custom character set. **Watch out for:** using `?a` (every possible character) for the 4 slots — that multiplies the guesses ~7× for nothing, since you already know they're only letters and digits.

### Problem 4 — "The locked report" *(Very Hard — file + slow hash)*

> *Dont let "Very Hard" scare you off, its labeled that because it has more steps, not because you gotta be some genius. Go slow, one step at a time, and youll see its actually very doable. Take your time with it.*

**The challenge:** a password-protected Word file, `quarterly_report.docx` (Office 2013). You can't hand a `.docx` straight to hashcat — you first turn it into a hash, then crack that. And this kind of hash is **slow by design** (built to resist cracking), so brute force is hopeless — wordlist + rules only.

**Walkthrough**
1. **Turn the file into a hash** with a helper tool (`office2john`):
   ```bash
   office2john quarterly_report.docx > p4.txt
   ```
   You'll get a long line like this (**this is a sample** — yours will have different numbers, because each file gets its own random "salt"):
   ```
   quarterly_report.docx:$office$*2013*100000*256*16*<16-byte salt hex>*<32 hex>*<40 hex>
   ```
   (*Salt* = random data mixed in before hashing, so the same password produces a different hash every time. The `100000` is how many times it re-hashes — that repetition is what makes it slow.)
2. **Pick the mode from the tag.** The `*2013*` in the line means Office 2013 → **`-m 9600`**. (Office 2007 → 9400, 2010 → 9500.) Don't guess — read the tag.
3. **Crack it the slow-hash way** — a wordlist, then rules on whatever's left:
   ```bash
   hashcat -m 9600 p4.txt /usr/share/wordlists/rockyou.txt
   hashcat -m 9600 p4.txt rockyou.txt -r rules/best64.rule
   hashcat -m 9600 p4.txt --show --username
   ```
   (`--username` just keeps the `filename:hash` label tidy in the output.)
4. The password you recover opens the document — the answer is that password, or a flag hidden inside the file.

**Practice it for real:** make your own `.docx`, set its password to `hashcat`, run the commands above with a wordlist that contains the word `hashcat`, and watch it crack. Do this once before the competition so you know your tools work.

**Watch out for:**
- Wrong year in the tag → wrong mode → "No hashes loaded." Always read the tag.
- Trying a brute-force mask (`-a 3`) on a slow hash → it'll still be running long after the clock runs out (§8).
- Office, PDF, KeePass, and 7-Zip files are all slow. Same recipe every time: **convert → match the mode → wordlist + rules → never brute-force.**

### Problem 5 — "The whole breach" *(Very Hard — the final boss)*

**The challenge:** a stolen user table — five MD5 hashes, all themed around one organization (University of Arizona: its mascot, founding year, and some leetspeak). It's one question worth all five answers, so you need every one. This puts every skill together.
```
8afa847f50a716e64932d995c8e7435a
bbb5d529a191f92f734b61afbea7a055
613536573a2f4366ba81c43448787b52
1a1c3f22fb9ab0176d7ffeb222e01416
1f3cbd3f6cb3626acc01709320ceb218
```
**Walkthrough** — work cheapest to most expensive, and keep chipping away at what's left.
1. **Hash type:** 32 hex, from an app database → **MD5** → mode `-m 0`.
2. **Cheap first pass — plain rockyou:**
   ```bash
   hashcat -m 0 p5.txt rockyou.txt
   ```
   Cracks the weak one: `princess`.
3. **rockyou + rules** for simple variations (added numbers, capitals, and so on):
   ```bash
   hashcat -m 0 p5.txt rockyou.txt -r rules/best64.rule
   ```
4. **Now chase the themed ones** that stock lists miss. Build `themed.txt`:
   ```
   wildcat
   wildcats
   beardown
   arizona
   tucson
   ```
   - The plain themed list cracks `beardown`:
     ```bash
     hashcat -m 0 p5.txt themed.txt
     ```
   - A theme word + the founding year → a **hybrid** (word, then 4 digits) cracks `arizona1885`:
     ```bash
     hashcat -m 0 p5.txt -a 6 themed.txt '?d?d?d?d'
     ```
   - A "leetspeak" spelling `W!ldc@ts` (capital `W`, with `i→!` and `a→@`) — `best64` won't make these swaps, and no stock rule reliably produces this exact mix, so the sure thing is to add the spelling straight into `themed.txt` and re-run it:
     ```bash
     echo 'W!ldc@ts' >> themed.txt
     hashcat -m 0 p5.txt themed.txt
     ```
     (To automate leet swaps in general, hashcat ships `rules/leetspeak.rule` and `rules/unix-ninja-leetspeak.rule` — just confirm they output the exact substitution you need before relying on them.)
5. **The last one is a code with a known shape, `UA-####`** (four digits), so brute-force just that part with a mask:
   ```bash
   hashcat -m 0 p5.txt -a 3 'UA-?d?d?d?d'
   ```
   → `UA-4821`.
6. **Line every hash up with its password** before you submit:
   ```bash
   hashcat -m 0 p5.txt --show
   ```
   This step matters: hashcat cracks hashes in whatever order is *fastest*, not the order they sit in your file, so `--show` is how you know which password belongs to which hash.
7. **Answers:** `princess` · `beardown` · `arizona1885` · `W!ldc@ts` · `UA-4821`

**Why it's the final boss:** no single command solves it. You go cheap → expensive, pull words from the scenario, and pick the right tool for each leftover (a rule here, a hybrid there, a mask for the code). **Watch out for:** stopping once you've got a few — all five are graded. And if an answer comes back as `$HEX[...]`, decode it before submitting (§11, item 1). Always trust `--show` order, not the order things scrolled past on screen (§7).

> **Bonus rounds (format coverage).** Problems 6–7 aren't harder than the finale — they drill two formats NCL loves that the five above didn't touch: a **Wi-Fi handshake** and a **salted Linux hash**. Both use the same cheap-first discipline.

### Problem 6 — "The guest Wi-Fi" *(Very Hard — Wi-Fi handshake, `-m 22000`)*

**The challenge:** a captured Wi-Fi handshake file (a `.pcapng`/`.cap` grabbed from the air). Recover the Wi-Fi password. You can't feed the capture to hashcat directly — you convert it to hashcat's `22000` format first.

> ⚖️ **Only ever do this against a network you own or are explicitly authorized to test.** Capturing someone else's handshake is illegal (see the guide intro).

**Walkthrough**
1. **Convert the capture** with `hcxpcapngtool` (from the `hcxtools` suite):
   ```bash
   hcxpcapngtool -o wifi.hc22000 capture.pcapng
   ```
   You'll get one or more lines (**this is a sample** — yours will differ):
   ```
   WPA*02*<MIC hex>*<AP MAC>*<client MAC>*<SSID hex>*<nonce + EAPOL hex>...
   ```
   (`WPA*01*` = a line built from a PMKID; `WPA*02*` = a line from a full 4-way handshake. Both crack with the same mode.)
2. **Mode is always `-m 22000`** for modern WPA/WPA2:
   ```bash
   hashcat -m 22000 wifi.hc22000 /usr/share/wordlists/rockyou.txt
   ```
3. **Wi-Fi keys are at least 8 characters** (the WPA minimum), so if a wordlist misses, use a mask built from what you *know* — a phone number, a street + ZIP, or the network name itself. Example, a 10-digit phone-style key:
   ```bash
   hashcat -m 22000 wifi.hc22000 -a 3 '?d?d?d?d?d?d?d?d?d?d'
   ```
4. **`--show`** maps the cracked key; that passphrase is your answer.

**Practice it for real:** capture *your own* home handshake with `hcxdumptool`, or use a sample `.pcapng` from the hcxtools/hashcat test files, then convert and crack a wordlist you seeded with the known password.

**Watch out for:**
- The old mode `2500` is **deprecated** — use `22000` (it handles both handshake and PMKID).
- A full brute of even an 8-char key is 95⁸ — do the keyspace math (§11, item 10) and prefer wordlists/targeted masks.

### Problem 7 — "The shadow file" *(Very Hard — salted Linux hash, `-m 1800`)*

**The challenge:** a line pulled from a Linux `/etc/shadow`. The `$6$` marks it as **sha512crypt** — salted *and* slow. Recover the password. (This hash is **real** — you can verify it; see the bottom of this problem.)
```
beardown:$6$Tucson99$nwroQ07sh4KOnzw/x7qS5CZNO6VuFwCBGrdRakmz0pvZxXqdDS8LyjJjyugPeiYK8O0yxEKaInOZxba1rVPdW0
```
The format is `username:$6$salt$hash`. The `$6$` is the type, `Tucson99` is the **salt** (random data mixed into the password before hashing, so the same password makes a different hash every time), and the long tail is the hash. That salt is exactly why online lookup sites can't help here.

**Walkthrough**
1. **Identify:** the `$6$` prefix → **sha512crypt** → mode `-m 1800`. (`$1$` = md5crypt/500, `$5$` = sha256crypt/7400, `$2y$` = bcrypt/3200.)
2. **Keep the `username:`** and use `--username` so hashcat maps it back cleanly. Save the line to `p7.txt`.
3. **Slow hash → wordlist + rules only, never brute:**
   ```bash
   hashcat -m 1800 --username p7.txt /usr/share/wordlists/rockyou.txt
   hashcat -m 1800 --username p7.txt rockyou.txt -r rules/best64.rule
   ```
4. **It's themed** (school + founding year), so if rockyou misses it, a themed hybrid lands it — word, then 4-digit year (put `beardown` in `themed.txt`):
   ```bash
   hashcat -m 1800 --username p7.txt -a 6 themed.txt '?d?d?d?d'
   ```
5. **Read the answer:**
   ```bash
   hashcat -m 1800 --username p7.txt --show
   ```
6. **Answer:** `beardown1885`

**Verify this hash yourself** (proof it's real, not a sample) — run:
```bash
openssl passwd -6 -salt Tucson99 'beardown1885'
```
and you'll get the exact hash shown above. That's the salt + password producing that hash.

**Watch out for:**
- sha512crypt is slow (thousands/sec even on a strong GPU) — a mask brute of anything long won't finish in time (§8). Wordlist/hybrid only.
- Never paste a salted hash into CrackStation — online tables only cover *unsalted* hashes (§9, §11 item 6).
- bcrypt (`$2y$`, `-m 3200`) and yescrypt (`$y$`) are even slower — same wordlist-first discipline.

> **Real-gym note — yescrypt (`$y$`).** The example above is sha512crypt (`$6$`), but modern Kali/Debian `/etc/shadow` now defaults to **yescrypt** (prefix `$y$`), and the actual NCL gym shadow challenge uses it. **Stock hashcat has no yescrypt mode**, and plain John often doesn't either — crack it on a system that uses yescrypt natively with John's OS-crypt fallback: `john --format=crypt shadow.txt` (slow, one hash at a time), or a recent John *jumbo* build with native yescrypt support. Everything else is identical: read the `$id$` prefix, keep the username, wordlist/hybrid only, never brute.

---

## Where to practice next

(Tool downloads and online tools moved up to §2.)

- **National Cyber League** — https://nationalcyberleague.org/ · **Cyber Skyline** gym (the NCL practice arena) — https://cyberskyline.com/
- **John Hammond** — password-cracking / CTF walkthrough videos — https://www.youtube.com/@_JohnHammond
- **OverTheWire** wargames — Linux + crypto fundamentals — https://overthewire.org/wargames/
- **picoCTF** — free, beginner-friendly CTF (crypto, forensics, more) — https://picoctf.org/

---

## Quick decision tree

- **Unsalted MD5/SHA1/NTLM?** → CrackStation first (instant), then `rockyou`.
- **Salted `$6$`/`$2$`/file hash?** → skip online tables → `rockyou + best64` → themed list → `OneRuleToRuleThemAll`.
- **Know the format (e.g. `Sky-XXXX`)?** → mask attack `-a 3`.
- **Still nothing?** → build a custom wordlist from the challenge scenario, then re-run rules.

---

*Tools referenced: hashcat, John the Ripper (Jumbo), hashid / Name-That-Hash, the `*2john` converters, CrackStation, CyberChef. Mode numbers verified against the official hashcat example-hashes list. Pair this with the Decode/Cryptography notes — some "password" challenges are really encoding puzzles in disguise.*
