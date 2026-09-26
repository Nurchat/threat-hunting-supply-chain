# Week 3 Deliverable: Data Processing, Normalization & MISP Integration

## 1. MISP Deployment Specification
* **Platform Architecture:** Containerized deployment utilizing Docker and Docker Compose (`misp-docker`).
* **Components:**
  * **MISP Core:** Web interface, REST API engine, PyMISP connector.
  * **Database:** MySQL 5.7 backend storing attributes, tags, and galaxy clusters.
  * **Integration Point:** Local endpoint exposed on `http://localhost:80` for API-driven IOC pushing.

## 2. IOC Processing & Normalization Pipeline
Threat feeds collected from open-source tools (VirusTotal, Shodan, public advisories) contain varied syntax, formatting artifacts (defanged URLs like `hxxp`, `[.]`), and duplicate records.

### Pipeline Workflow (`scripts/filter_normalize.py`):
1. **Sanitization:** De-fanging brackets removal (`[.]` \(\to\) `.`) and string whitespace trimming.
2. **Regex-Based Validation:** Parsing indicators against strict RFC formats for IPv4 addresses, FQDN domains, and 64-character SHA-256 hashes.
3. **Deduplication:** State tracking via hash sets to eliminate redundant alert attributes.
4. **Enrichment & MISP Formatting:** Converting valid artifacts into native MISP Event JSON schema, assigning appropriate categories (`Payload delivery`, `Network activity`) and enabling the `to_ids` flag for export into SIEM/Snort rules.

## 3. Imported IOC Evidence

| Indicator Value | Type | Category | Threat Context |
| :--- | :--- | :--- | :--- |
| `83a0429f9e2b1049c5...` | `sha256` | Payload delivery | Poisoned package `setup.py` stager |
| `198.51.100.42` | `ip-dst` | Network activity | Exfiltration drop-server identified via VT |
| `malicious-pypi-mirror.org`| `domain` | Network activity | Fake upstream registry mirror |
