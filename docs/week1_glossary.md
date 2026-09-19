# Week 1 Deliverable: CTI Fundamentals & Threat Taxonomy

## 1. Domain-Specific CTI Glossary
* **Software Supply Chain Compromise:** Insertion of malicious code or backdoors into software components, open-source dependencies, or build systems prior to end-user deployment.
* **Artifact Poisoning:** Altering compiled binaries, archive packages, or code dependencies to include unauthorized payloads while masquerading as legitimate releases.
* **Dependency Confusion:** Exploiting package managers by submitting public packages with higher version numbers than internal private packages, forcing build systems to pull malicious code.
* **Typosquatting:** Registering packages with names visually or typographically similar to legitimate packages (e.g., `colorma` instead of `colorama`).
* **Pyramid of Pain (Supply Chain Perspective):**
  * *Trivial:* Package MD5/SHA-256 hashes (easily altered by regenerating builds).
  * *Simple:* Registry IP addresses / staging hosting providers.
  * *Tough/Challenging:* Cryptographic signing validation and anomalous build-time behaviors (TTPs).
* **Traffic Light Protocol (TLP):** Standardized labels (TLP:RED, AMBER, GREEN, CLEAR) governing how threat intelligence data may be shared across security communities.

## 2. Threat Classification Matrix (ENISA Threat Landscape Taxonomy)

| Component | Element / Vector | Description |
| :--- | :--- | :--- |
| **Threat Actor** | Financially Motivated Cybercrime | Deploying infostealers to capture developer credentials and cloud tokens. |
| **Threat Actor** | Nation-State / APT Actors | Long-term cyber espionage and backdoor injection into targeted upstream vendors. |
| **Attack Vector** | Compromised Upstream Dependencies | Poisoning open-source modules in public package repositories. |
| **Attack Vector** | CI/CD Build Pipeline Tampering | Intercepting runners to alter build artifacts before signature generation. |
| **Target Asset** | Developer Workstations | Hijacking SSH keys, tokens (`~/.aws/credentials`), and code signing keys. |
