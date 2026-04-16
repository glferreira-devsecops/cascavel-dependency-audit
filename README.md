<p align="center">
  <img src="https://img.shields.io/badge/📦_CASCAVEL-Dependency_Audit-DC3545?style=for-the-badge&labelColor=1a1a2e" />
</p>

<h1 align="center">Cascavel Dependency Audit</h1>
<h3 align="center">Multi-Ecosystem CVE Scanner for CI/CD Pipelines</h3>

<p align="center">
  <a href="https://github.com/marketplace/actions/cascavel-dependency-audit"><img src="https://img.shields.io/badge/GitHub_Marketplace-Available-2ea44f?style=flat-square&logo=github" /></a>
  <img src="https://img.shields.io/badge/Ecosystems-7-blueviolet?style=flat-square" />
  <img src="https://img.shields.io/badge/SARIF-Supported-blue?style=flat-square" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-00D4FF?style=flat-square" /></a>
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET_Tecnologia-Open_Source-FF6B00?style=flat-square" /></a>
</p>

<p align="center">
  Scan project dependencies for known CVEs using the OSV database.<br />
  Auto-detects npm, pip, Go, Ruby, Rust, PHP Composer, and Maven.<br />
  <strong>Zero configuration. SARIF output. CVE ignore lists.</strong>
</p>

---

## ⚡ Quick Start

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
```

Auto-detects your project's ecosystem and scans for vulnerabilities.

## 🎯 Features

- 📦 **7 ecosystems** — npm, pip, Go, Ruby, Rust, PHP, Java
- 🔍 **Auto-detection** — finds package files automatically
- 🌐 **OSV database** — queries Google's Open Source Vulnerability DB
- 🔒 **SARIF output** — GitHub Security tab integration
- 🚫 **CVE ignore list** — suppress known/accepted risks
- 📊 **GitHub Step Summary** — results table in workflow run
- ⚡ **npm audit fallback** — uses native npm audit when available
- 🔷 **govulncheck** — uses Go's official vuln checker when available

## 📖 Usage

### Auto-detect and scan

```yaml
name: Security
on: [push, pull_request]

jobs:
  dependency-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glferreira-devsecops/cascavel-dependency-audit@v1
```

### Specific ecosystems with ignore list

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  with:
    ecosystems: 'npm,pip'
    severity: 'high'
    ignore-cves: 'CVE-2024-1234,GHSA-xxxx-yyyy'
```

### Upload SARIF to GitHub Security

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  id: audit
  with:
    fail-on-findings: 'false'

- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: ${{ steps.audit.outputs.sarif-path }}
```

## 🔍 Supported Ecosystems

| Ecosystem | Files Detected | Backend |
|:----------|:---------------|:--------|
| **npm** | `package.json`, `package-lock.json`, `yarn.lock` | npm audit + OSV |
| **pip** | `requirements.txt`, `Pipfile.lock`, `pyproject.toml` | OSV API |
| **Go** | `go.mod`, `go.sum` | govulncheck + OSV |
| **Ruby** | `Gemfile`, `Gemfile.lock` | OSV API |
| **Rust** | `Cargo.toml`, `Cargo.lock` | OSV API |
| **PHP** | `composer.json`, `composer.lock` | OSV API |
| **Java** | `pom.xml`, `build.gradle` | OSV API |

## ⚙️ Inputs

| Input | Description | Default |
|:------|:------------|:--------|
| `path` | Project root | `.` |
| `severity` | Minimum: `low`, `medium`, `high`, `critical` | `medium` |
| `fail-on-findings` | Block pipeline on CVEs | `true` |
| `ecosystems` | Ecosystems to scan (or `auto`) | `auto` |
| `ignore-cves` | Comma-separated CVE IDs to skip | _(none)_ |
| `sarif-output` | Generate SARIF report | `true` |

## 📤 Outputs

| Output | Description |
|:-------|:------------|
| `total-vulnerabilities` | Total CVEs found |
| `critical-count` | Critical count |
| `high-count` | High count |
| `affected-packages` | Affected package count |
| `report-path` | JSON report path |
| `sarif-path` | SARIF report path |

## 📄 License

MIT — [RET Tecnologia](https://rettecnologia.org)

---

<p align="center">
  <sub>📦 Built by <a href="https://github.com/glferreira-devsecops">@glferreira-devsecops</a> at <a href="https://rettecnologia.org">RET Tecnologia</a></sub>
</p>
