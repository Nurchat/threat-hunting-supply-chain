# Week 2 Deliverable: OSINT Reconnaissance & Data Source Mapping

## 1. OSINT Investigations

### Shodan Reconnaissance
Targeting exposed supply chain infrastructure and unauthenticated build controllers:
* **Exposed Jenkins Controller Panels:** `http.title:"Dashboard [Jenkins]"`
* **Exposed Sonatype Nexus Artifact Registries:** `http.title:"Nexus Repository Manager" 200`
* **Public/Exposed GitLab Instances:** `http.title:"GitLab" -http.status:302`

### VirusTotal Payload Profiling
* **Target Sample:** Backdoored installer / `setup.py` stager.
* **Extracted Attributes:** Process execution tree, base64 payload strings, and external HTTP callbacks.
* **IOC Extraction:** File hash (SHA-256), stage-2 drop URL, and associated external IP addresses.

### Maltego Transformation Graph
* **Seed:** Malicious package author email / domain.
* **Transformations:**
  1. Author Email $\to$ Associated Domains (Reverse WHOIS).
  2. Domain $\to$ Resolved DNS A-Records (C2 Hosting IPs).
  3. IP Address $\to$ Autonomous System Number (ASN) and Co-located Infrastructure.

## 2. Detection & Data Source Mapping Matrix

| Attack Stage | Adversary Activity | Primary Data Source | Event Identifier / Metric |
| :--- | :--- | :--- | :--- |
| **Initial Delivery** | Downloading typosquatted library | Web Proxy / DNS Logs | Outbound HTTP GET to anomalous registry domain |
| **Execution** | Package installer spawning shell | Endpoint Logs (Sysmon) | Event ID 1 (Process Create: `pip`/`python` spawning `powershell.exe`/`bash`) |
| **Credential Theft** | Reading secrets from environment | Auditd / OS Logs | Unauthorized read events on `~/.aws/credentials` or `id_rsa` |
| **Command & Control** | Exfiltration of captured keys | Network Flow / Firewall | Outbound traffic to uncataloged external IPs on non-standard ports |
