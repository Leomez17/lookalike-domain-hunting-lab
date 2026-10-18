# Lookalike Domain Hunting: HMRC Brand Impersonation

Proactive discovery and triage of registered lookalike domains that could be used for HMRC-themed phishing and refund fraud. Built as preparation for fraud-prevention work and as part of my SOC portfolio.

**Environment:** Kali Linux · dnstwist · whois · dig · jq · curl · Cert Spotter API · urlscan.io
**Date:** October 2026 · **Scope:** public OSINT only; no suspect site was browsed directly. Indicators are defanged.

## Results at a glance

| Metric | Count |
|---|---|
| Registered permutations | 97 |
| HMRC defensive registrations | 19 |
| Closed as benign on evidence | 4 |
| Placed on monitoring | 3 |
| HIGH: suspected staged phishing infrastructure | 1 |

**Key finding:** `onlinehmrc[.]com` is outside HMRC's defensive set. It is privacy-masked, about one year old, mail-enabled, has a Let's Encrypt certificate issued 1 Aug 2026, and is live on a Frankfurt-hosted server with no public scan history. The page was an untitled 1 KB placeholder, so the infrastructure appears to be staged but not yet serving a lure.

## Method

1. **Baseline:** `dnstwist --registered hmrc.gov.uk`. `.gov.uk` cannot be squatted, but `.uk` neighbours can (both hits were defensive).
2. **Main hunt:**
   ```bash
   dnstwist --registered --mxcheck --geoip --threads 20 \
     --tld tlds.txt --dictionary words.txt --format csv hmrc.com > 02_lookalikes.csv
   ```
3. **Cluster** defensive registrations by shared IP / name servers (Com Laude, Demys).
4. **Triage** the shortlist with WHOIS (age, registrar, privacy), MX records, certificate transparency (Cert Spotter; crt.sh was returning 502), hosting WHOIS and a **private** urlscan.io scan.

## Findings register

| Domain | Created | Registrar | Signals | Verdict |
|---|---|---|---|---|
| onlinehmrc[.]com | 2025-09-26 | Dynadot (privacy) | Live host, MX, LE cert, no scan history | **HIGH** |
| hmrec[.]com | 2026-03-04 | Namecheap (privacy) | Mail forwarding, LE cert, now parked | MEDIUM |
| hmrc[.]net | 2025-01-07 | Gname (redacted) | Exact brand, parked | MEDIUM |
| hmrc[.]site | 2021-09-30 | Namecheap | Exact brand, parked | LOW |
| hmrc[.]org | 2001-02-08 | eNom | Predates HMRC (formed 2005) | LOW |
| online-hmrc[.]com | 2021-08-31 | Com Laude | Registrant: HM Revenue & Customs | BENIGN |
| hrmrc[.]com | 2023-10-20 | Turkish registrar | Named unrelated company | BENIGN |
| hmrdc[.]com | 2006-10-28 | PDR | Registrant matches acronym | BENIGN |
| hrrc[.]com | 1998-01-20 | Network Solutions | Long-standing, unrelated | BENIGN |

## Analyst notes

- The obvious fraud keywords are already defensively registered, so hunting effort goes to the gaps.
- A certificate pivot first suggested a compromised business host; later DNS showed that domain parked, so the assessment was revised. The pivot domain is withheld here as it may belong to an unrelated party.
- Shared Namecheap parking IPs were not treated as a link between domains.
- dnstwist recorded no A record for the HIGH domain, but a later `dig` resolved it. High-priority domains need scheduled re-resolution.
- OPSEC: one early urlscan submission was public. Scans of suspected infrastructure should be private by default.

## MITRE ATT&CK

T1583.001 Acquire Infrastructure: Domains · T1583.004 Server · T1608.003 Install Digital Certificate · T1566.002 Spearphishing Link

## Recommendations

1. Block the HIGH domain and its IP at email and web gateways.
2. Route a takedown through the organisation's process (NCSC Takedown Service for UK government brands) using the evidence pack.
3. Add missed keyword variants to the defensive registration review.
4. Daily re-resolution and CT monitoring of MEDIUM and LOW domains.
5. Private re-scan around the certificate renewal (~30 Oct 2026).

## Evidence files

`01_govuk_baseline.txt` → `17_urlscan_dom.html`: numbered in investigation order, including the failed crt.sh output kept as evidence of the source pivot. Files are in [`evidence/`](evidence/). Full write-up: [`report/Lookalike_Domain_Hunting_Report.docx`](report/Lookalike_Domain_Hunting_Report.docx). Web version: [`docs/index.html`](docs/index.html).

---
Leonard Abanobi · SOC Analyst · CompTIA Security+ · [Portfolio](https://leomez17.github.io/Cybersecurity-Portfolio/) · [GitHub](https://github.com/Leomez17)
