# OSINT — NCL Field Guide

*By Ruta Rezene · University of Arizona · Women in Cybersecurity (WiCyS)*

OSINT is "the answer is already public, go find it." You're given a photo, a username, a domain, a flag image, and you dig through open sources to pull out a name, a location, a date, or a hidden `SKY-` flag. Everything here uses public data only. Never use these techniques to stalk, dox, or investigate a real private person outside an authorized challenge.

---

## 1. Workflow

1. **Read the question for the exact ask** (a city? a full name? a date? a flag?). Answer format is a strong hint.
2. **Extract every clue** from what you're given: text, metadata, the image itself, the URL.
3. **Pivot** from one clue to the next (username to profile, photo to place, domain to owner).
4. **Corroborate** with a second source before you submit. One match is a guess.
5. **Format the answer** exactly as asked (full flag, decimal coords, YYYY-MM-DD, etc.).

**Golden rule:** the metadata and the pixels are two separate sources. Always check both.

---

## 2. Toolbox

| Tool | Use it for |
|---|---|
| **exiftool** | EXIF metadata: GPS, camera, timestamps, author, software |
| **Google / dorks** | Targeted search with operators (below) |
| **Reverse image search** | Google Lens, Yandex (best for faces/places), TinEye, Bing Visual |
| **whois / dig / nslookup** | Domain owner, registrar, name servers, IPs |
| **Wayback Machine** | Deleted/old versions of a page (web.archive.org) |
| **Sherlock / WhatsMyName** | Find a username across many sites |
| **Shodan / Censys** | Internet-facing devices, banners, open services |
| **Maps + Street View** | Confirm a location from landmarks/signs |
| **GeoHints / SunCalc** | Geolocation aids (bollards, plates, sun angle) |

---

## 3. Core techniques

**Google dorks** (stack them):
```
site:example.com filetype:pdf
intitle:"index of" "backup"
"john smith" (linkedin OR twitter OR github)
inurl:admin site:target.org
```

**Image metadata — always run first:**
```bash
exiftool -a -G1 photo.jpg        # all tags, grouped
exiftool -gpslatitude -gpslongitude photo.jpg
```
GPS prints as DMS (deg/min/sec). Convert to decimal for maps: `decimal = deg + min/60 + sec/3600` (negative for S and W).

**Geolocation from the pixels** (when there's no GPS): read signs and language, license-plate colors/format, road markings, power poles, architecture, vegetation, and mountains on the horizon. Reverse-image in **Yandex** first, it beats Google on places and faces. Drop into Street View to confirm.

**Username / people pivots:** a handle on one site usually reuses across others. Run it through Sherlock, then read bios, follower lists, and old posts. Profile pictures reverse-image too.

**Domain / infra:**
```bash
whois example.com      # registrant, dates, registrar
dig example.com any    # A, MX, NS, TXT records
```
Then check the Wayback Machine for pages that are "gone." `crt.sh` lists issued certs, which leak subdomains.

**Flag images:** NCL hides `SKY-` flags in EXIF comments, in the filename, or in the visible image (zoom, adjust brightness/contrast). Run exiftool and `strings` on the file before anything clever.

---

## 4. Common pitfalls

- **Skipping the pixels or skipping the metadata.** They're independent; check both.
- **Google-only reverse search.** Yandex and Bing find things Google won't, especially faces and foreign places.
- **Submitting DMS instead of decimal** (or wrong sign on S/W). Re-read the required format.
- **Trusting one source.** Corroborate before submitting.
- **Ignoring the Wayback Machine** when a linked page is dead or edited.
- **Over-researching a private individual.** Stay inside the challenge scope.

---

## 5. Quick decision tree

- **Photo?** exiftool for GPS, then reverse-image (Yandex), then read the scene.
- **Username?** Sherlock, then pivot through bios and old posts.
- **Domain/IP?** whois + dig, then crt.sh and Wayback.
- **"Find the flag in this image"?** exiftool + strings + zoom/brightness.
- **Stuck?** Re-read the question, name the single fact you still need, and search for only that.
