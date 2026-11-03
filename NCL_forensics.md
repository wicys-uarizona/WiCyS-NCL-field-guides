#  Forensics

Forensics in NCL is "a file is lying to you, find the truth". Extensions are fake, data is hidden inside other data, things look deleted but aren't. The whole category rewards one habit: **never trust the file name, always read the bytes.**

> **Rule #1:** never trust the file name. Read the bytes. **Rule #2:** accuracy counts, so verify before you submit. Don't spray guesses.

## 0. Team Workflow (first 5 minutes)

- **Claim challenges** in the team chat: `FOR – <challenge> – <name>`. Each challenge gets one owner and one backup.
- **Verify, then copy.** Check the provided MD5 if one is given (`md5sum`). A truncated download wastes hours. Work on a copy.
- **Read every question first.** Later questions often hint at where the earlier answers live.
- **Keep a chain log:** "file X turned out to be Y." Multi-step challenges are easy to lose track of.
- **Stuck 20+ min?** Post what you tried and hand it off.


## 1. Links to solved NCL challenge walkthroughs reference repo: 

**Magic Bytes**  **Link:** https://trove.cyberskyline.com/fcef21cfbe47480b8eacc9f532e26803> (REF: when files won't open)

**File Carving** **Link:** https://trove.cyberskyline.com/ff55c18374c84109b32b95252309185d (REF: Hidden Embedded Files in images)

**Doctor** **Link:** https://trove.cyberskyline.com/8c97492b13224bd88bfbfb14eb0401cc (REF: Stego)

**PDF Examination** **Link:** https://trove.cyberskyline.com/1bbd0e56afbb46c69ea612129a93fae2 (REF: Redacted info)

**1. Your forensics first-pass, run on every file:**

```bash
file suspect            # real type, from magic bytes
xxd suspect | head      # look at the bytes yourself
exiftool suspect        # author, tool, GPS, timestamps
strings -n 6 suspect    # buried text (add -el for UTF-16 Windows strings)
binwalk suspect         # files hidden inside files
binwalk -Me suspect     # extract recursively (matryoshka mode)
find _suspect.extracted -type f -exec file {} +   # identify everything carved
```

**Magic bytes worth memorizing** (the first bytes of a file identify its true type):

| Hex | Type | Hex | Type |
|---|---|---|---|
| `FF D8 FF` | JPEG | `50 4B 03 04` | ZIP / docx / xlsx / jar / apk |
| `89 50 4E 47 0D 0A 1A 0A` | PNG | `1F 8B` | gzip |
| `47 49 46 38` | GIF | `52 61 72 21` | RAR |
| `25 50 44 46` | PDF | `7F 45 4C 46` | ELF |
| `4D 5A` | EXE/DLL | `D4 C3 B2 A1` / `0A 0D 0D 0A` | PCAP / PCAPNG 


Reference: Wikipedia "List of file signatures". Hex editor of choice: HexEd.it (browser) or `xxd`/`hexedit` on Linux.

---
## 2. Recurring NCL Patterns

**Wrong or broken header.** Strings like `IHDR` / `IDAT` / `IEND` mean the file is a PNG; `JFIF` means JPEG. Overwrite the header in place. A valid PNG always starts with these 12 bytes:
```bash
printf '\x89PNG\r\n\x1a\n\x00\x00\x00\x0D' | dd of=file bs=1 conv=notrunc
```
Watch the length difference: a JPEG signature is 12 bytes and PNG's is 8, so the leftover bytes need fixing too. `pngcheck -v` flags CRC or size errors.

**Files inside files.** "How many files?" means count the headers binwalk finds. If binwalk misses images, try `foremost` or `scalpel`.

**Office documents are ZIPs.** Run `unzip doc.docx -d d`. Then:
- Compare `d/word/media/` against what the document visibly shows. An extra image is the hidden one.
- Read `docProps/core.xml` and `app.xml` for author, company, and revision.
- Run `olevba` for macros.

**PDFs.** A black box is usually drawn *over* the text, not a real redaction.
```bash
pdftotext file.pdf -        # dumps text, including text under boxes
exiftool file.pdf           # Creator, Producer, CreatorTool, PDFVersion
pdfimages -all file.pdf out # if the text is an image, OCR it
```

**Git repos.** Run `ls -a`; a `.git` folder means the full history is there. "Deleted" is not gone.
```bash
git log --all --oneline --stat   # every commit on every branch
git log --all -p -S "SKY-"       # commit that added/removed the flag
git branch -a; git stash list; git reflog; git tag
```

**Encoding chains.** Run `file` after **every** step: decode → extract → convert → crack.
- Base64-looking text: `base64 -d`.
- EBCDIC (IBM): long runs of `0x40` where you'd expect spaces. Convert with `dd conv=ascii`.
- Unknown formats: research them, then find a parser (e.g. `pip install` one in a venv).

**Archives & passwords.**
```bash
zip2john s.zip > h && john h --wordlist=rockyou.txt   # also pdf2john / office2john
john --format=<fmt> --rules=best64 ...                # when the plain wordlist fails
hashcat -m 1000 ntlm.txt rockyou.txt                  # NTLM; or CrackStation for easy ones
```
Hash length tells you the type: 32 hex characters = MD5 or NTLM, 40 = SHA-1, 64 = SHA-256.

---

you the type: 32 hex characters = MD5 or NTLM, 40 = SHA-1, 64 = SHA-256.
## 3. Images & Stego

- `exiftool -a -G1` for GPS (convert DMS to decimal for a map), comments, and editing software.
- PNG/BMP: `zsteg`. JPEG: `steghide extract -sf img.jpg` (blank password first), then `stegseek img.jpg rockyou.txt`.
- Aperi'Solve or `stegsolve` for bit planes. Also check for data after `FF D9` (JPEG) or `IEND` (PNG).

## 4. Memory Dumps (Volatility 3)

Install a released version (`pipx install volatility3`). Random git checkouts give inconsistent output.
```bash
vol -f mem windows.info          # OS / build
vol -f mem windows.envars        # COMPUTERNAME, USERNAME, user profile paths
vol -f mem windows.pstree        # what was running (also pslist, psscan)
vol -f mem windows.cmdline       # command lines: often the shortcut
vol -f mem windows.netscan       # connections
vol -f mem windows.filescan | grep -i <user|name>
vol -f mem -o out windows.dumpfiles --virtaddr <addr>
vol -f mem windows.hashdump      # NTLM hashes → crack
```

This is a **Volatility 3** memory forensics challenge. First decompress and verify:
![img.png](img.png)
```bash
7z e memdump.7z
md5sum memdump.mem      # should be 6dc7989143b7fc693315d24df21a4b0f
```

Then run Volatility plugins, each answers one question:

```bash
./vol.py -f memdump.mem windows.info.Info            # OS (Windows)
./vol.py -f memdump.mem windows.envars.Envars        # COMPUTERNAME + USERNAME, C:\Users\...
./vol.py -f memdump.mem windows.filescan.FileScan | grep <user>   # find the file + its virtual address
./vol.py -f memdump.mem -o ./output windows.dumpfiles.DumpFiles --virtaddr 0xe000...   # extract it
# the file is a SQLite DB -> open in SQLite Browser -> find "cloud"'s real name
./vol.py -f memdump.mem windows.hashdump.Hashdump    # NTLM hashes
```


A dumped file might be SQLite: `sqlite3 f.db ".tables"`, then `SELECT * FROM <table>;`.


`foremost` and `scalpel` are alternative carvers that reconstruct files by header/footer signatures and are sometimes better at images.

---

## 5. Disk Images (quick reference)

- `mmls` (partitions), then `fls -r -o <off>` (files; `*` = deleted), then `icat -o <off> img <inode>`.
- GUI: Autopsy or FTK Imager.
- Windows artifacts:
  - Registry hives: Registry Explorer / RegRipper.
  - `.evtx` event logs: 4624 logon, 4625 failed logon, 4720 user created, 7045 service installed.
  - Also Prefetch, LNK files, and the Recycle Bin (`$I`/`$R`).



### Learning tips
You will almost never see mainframe/EBCDIC/RACF outside this challenge, and that's the point: it teaches you to research an unknown format from scratch and chain `file` → decode → extract → convert → crack. That methodology transfers to everything. EBCDIC's tell is runs of `0x40` (its space character) where you'd expect `0x20`.

PNG's full header is always those same 12 bytes (signature + first chunk length). Keep a known-good PNG around to copy headers from. The `IDAT`/`IEND`/`IHDR` chunk names are a dead giveaway that a mislabeled file is really a PNG.

Volatility is *the* memory forensics tool and a huge employability skill (DFIR, IR). Core Windows plugins to know: `windows.info`, `windows.pslist`/`pstree`, `windows.cmdline`, `windows.netscan`, `windows.filescan`, `windows.dumpfiles`, `windows.hashdump`. Vol3 dropped the profile system of Vol2, so you just point it at the dump. Always verify the dump's md5 first, a truncated download wastes hours.

Every modern Office file (docx, xlsx, pptx) is a ZIP. So are JARs, APKs, EPUBs, and many others. When `file` says "Zip archive" but the extension says something else, unzip it and explore. This one trick solves a lot of document forensics.

"Carving" = finding files inside a blob by their magic bytes and cutting them out. Multiple files concatenated is a classic. The count question is just "how many headers did binwalk find". Always run `file` on each carved piece, since extensions are guesses.

Deleting a file and committing does **not** remove it from history, it's still in `.git`. This is exactly how real secrets leak (an API key committed once, "removed" later, still public forever). Lesson: if a secret ever touched a repo, rotate it; don't just delete it.