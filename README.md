<p align="center">
  <img src="https://img.shields.io/badge/%F0%9F%93%A6_CASCAVEL-Dependency_Audit-DC3545?style=for-the-badge&labelColor=0D1117" />
</p>

<h1 align="center">📦 Cascavel Dependency Audit</h1>

<p align="center">
  <strong>Multi-ecosystem CVE scanner for CI/CD pipelines.</strong><br />
  <em>Auto-detect. Query OSV. Block vulnerable deploys. Zero config.</em>
</p>

<p align="center">
  <a href="https://github.com/marketplace/actions/cascavel-dependency-audit"><img src="https://img.shields.io/badge/GitHub%20Marketplace-Cascavel%20Dependency%20Audit-2ea44f?style=flat-square&logo=github" alt="Marketplace" /></a>
  <img src="https://img.shields.io/badge/ecosystems-7-7C3AED?style=flat-square" alt="7 ecosystems" />
  <img src="https://img.shields.io/badge/SARIF-supported-3B82F6?style=flat-square" alt="SARIF" />
  <img src="https://img.shields.io/badge/CVE%20database-OSV-10B981?style=flat-square" alt="OSV" />
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-EAB308?style=flat-square" alt="MIT" /></a>
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/by-RET%20Tecnologia-FF6B00?style=flat-square" alt="RET" /></a>
</p>

<br />

<p align="center">
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-why-cascavel">Why?</a> •
  <a href="#-ecosystems">Ecosystems</a> •
  <a href="#-advanced-usage">Advanced</a> •
  <a href="#-inputs">Inputs</a> •
  <a href="#-outputs">Outputs</a>
</p>

---

## 🚀 Quick Start

```yaml
name: Security
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glferreira-devsecops/cascavel-dependency-audit@v1
```

> Auto-detects your package files, queries the **Google OSV database** for known CVEs, and blocks the pipeline if vulnerabilities are found.

---

## 💡 Why Cascavel?

| | Cascavel | npm audit | pip-audit | Other tools |
|:--|:---------|:----------|:----------|:------------|
| **Languages** | 7 ecosystems | npm only | pip only | Usually 1-2 |
| **Setup** | Zero config | `npm ci` first | `pip install` first | Config files |
| **CVE Database** | Google OSV (all sources) | npm advisories | PyPI only | Varies |
| **SARIF** | Native | ❌ | ❌ | Often paid |
| **CVE Ignore** | Built-in | `.npmrc` | via args | Varies |
| **Cost** | Free | Free | Free | Often limits |

### How it works

```
1. 📁 Detect package files (auto or manual)
2. 📋 Extract dependencies and versions
3. 🌐 Query Google OSV API for each package
4. 📊 Classify by severity (CVSS score)
5. 📄 Generate JSON + SARIF reports
6. ✅ Pass or ❌ block the pipeline
```

---

## 🔍 Ecosystems

| Ecosystem | Auto-detected files | Scanner backend |
|:----------|:-------------------|:----------------|
| **npm** | `package.json` · `package-lock.json` · `yarn.lock` | Native `npm audit` + OSV fallback |
| **pip** | `requirements.txt` · `Pipfile.lock` · `pyproject.toml` · `setup.py` | OSV API (PyPI) |
| **Go** | `go.mod` · `go.sum` | Native `govulncheck` + OSV fallback |
| **Ruby** | `Gemfile` · `Gemfile.lock` | OSV API (RubyGems) |
| **Rust** | `Cargo.toml` · `Cargo.lock` | OSV API (crates.io) |
| **PHP** | `composer.json` · `composer.lock` | OSV API (Packagist) |
| **Java** | `pom.xml` · `build.gradle` · `build.gradle.kts` | OSV API (Maven) |

> **Smart fallbacks:** Uses native tools (`npm audit`, `govulncheck`) when available for richer results, then falls back to the universal OSV API.

---

## 🔧 Advanced Usage

### Scan specific ecosystems only

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  with:
    ecosystems: 'npm,pip'
    severity: 'high'
```

### Ignore accepted CVEs

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  with:
    ignore-cves: 'CVE-2024-1234,GHSA-xxxx-yyyy-zzzz'
```

### Upload SARIF to GitHub Security tab

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

### Critical-only mode (fast, strict)

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  with:
    severity: 'critical'
    fail-on-findings: 'true'
```

### Use outputs for custom logic

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  id: audit
  with:
    fail-on-findings: 'false'

- name: Notify team
  if: steps.audit.outputs.critical-count > 0
  run: |
    echo "🔴 ${{ steps.audit.outputs.critical-count }} critical CVEs found!"
    echo "📦 ${{ steps.audit.outputs.affected-packages }} packages affected"
```

### Monorepo scanning

```yaml
- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  with:
    path: './services/api'
    ecosystems: 'npm'

- uses: glferreira-devsecops/cascavel-dependency-audit@v1
  with:
    path: './services/ml'
    ecosystems: 'pip'
```

---

## ⚙️ Inputs

| Input | Description | Required | Default |
|:------|:------------|:--------:|:--------|
| `path` | Project root to scan | No | `.` |
| `severity` | Minimum: `low` / `medium` / `high` / `critical` | No | `medium` |
| `fail-on-findings` | Block pipeline on findings | No | `true` |
| `ecosystems` | Comma-separated list or `auto` | No | `auto` |
| `ignore-cves` | Comma-separated CVE/GHSA IDs to skip | No | _(none)_ |
| `max-age-days` | Only report CVEs published within N days | No | `0` (all) |
| `sarif-output` | Generate SARIF report | No | `true` |

## 📤 Outputs

| Output | Description | Example |
|:-------|:------------|:--------|
| `total-vulnerabilities` | Total CVEs found | `5` |
| `critical-count` | Critical severity | `1` |
| `high-count` | High severity | `3` |
| `affected-packages` | Packages with CVEs | `4` |
| `report-path` | JSON report path | `.cascavel/dependency-report.json` |
| `sarif-path` | SARIF report path | `.cascavel/dependency.sarif` |

---

## 📊 Example Output

```
  ╔══════════════════════════════════════════════════╗
  ║  📦 CASCAVEL DEPENDENCY AUDIT v1.0.0           ║
  ║  Multi-Ecosystem CVE Scanner                     ║
  ║  RET Tecnologia · https://rettecnologia.org      ║
  ╚══════════════════════════════════════════════════╝

  📂 Path:       .
  🎯 Threshold:  medium
  🔍 Ecosystems: npm,pip

  ────────────────────────────────────────────────────

  📦 NPM Dependencies
  ────────────────────────────────────────────────────

  🔴 [CRITICAL] GHSA-qwcr-r2fm-qhg7
     📦 lodash@4.17.20 (npm)
     📝 Prototype Pollution in lodash
     🔗 Aliases: CVE-2021-23337

  🟠 [HIGH] GHSA-jf85-cpcp-j695
     📦 express@4.17.1 (npm)
     📝 Open Redirect in express

  📊 Scanned 47 npm packages

  🐍 Python Dependencies
  ────────────────────────────────────────────────────

  🟠 [HIGH] PYSEC-2024-28
     📦 requests@2.28.0 (pip)
     📝 Certificate verification bypass
     🔗 Aliases: CVE-2024-35195

  📊 Scanned 12 Python packages

  ══════════════════════════════════════════════════════
  📊 AUDIT RESULTS
  ──────────────────────────────────────────────────────
  🔴 Critical:          1
  🟠 High:              2
  🟡 Medium:            0
  🔵 Low:               0
  ──────────────────────────────────────────────────────
  📋 Total CVEs:        3
  📦 Affected packages: 3

  ❌ Pipeline blocked: 3 vulnerability(ies) found

  📦 Cascavel Dependency Audit by RET Tecnologia
```

---

## 🌐 About the OSV Database

This action uses [Google OSV](https://osv.dev/) — the largest open-source vulnerability database, aggregating data from:

- **GitHub Security Advisories (GHSA)**
- **National Vulnerability Database (NVD/CVE)**
- **Python Security Advisories (PYSEC)**
- **Rust Advisories (RUSTSEC)**
- **Go Vulnerability Database**
- **RubyGems Advisories**
- And many more sources

---

## 🔗 Cascavel Security Suite

| Action | Description | Status |
|:-------|:------------|:------:|
| [🐍 Secret Scanner](https://github.com/marketplace/actions/cascavel-secret-scanner) | Detect hardcoded credentials | ✅ Live |
| [🛡️ Header Guard](https://github.com/marketplace/actions/cascavel-header-guard) | HTTP security headers analysis | ✅ Live |
| [📦 Dependency Audit](https://github.com/marketplace/actions/cascavel-dependency-audit) | CVE scanning for dependencies | ✅ Live |

### Full security pipeline

```yaml
name: Cascavel Security Suite
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: glferreira-devsecops/cascavel-secret-scanner@v1
      - uses: glferreira-devsecops/cascavel-dependency-audit@v1
      - uses: glferreira-devsecops/cascavel-header-guard@v1
        with:
          urls: 'https://staging.your-app.com'
```

---

## 📄 License

[MIT](LICENSE) — free for personal and commercial use.

---

<p align="center">
  <a href="https://rettecnologia.org"><img src="https://img.shields.io/badge/RET%20Tecnologia-Software%20Engineering%20%C2%B7%20Cybersecurity-0D1117?style=for-the-badge&labelColor=FF6B00" /></a>
</p>

<p align="center">
  <sub>Built with ❤️ by <a href="https://github.com/glferreira-devsecops">Gabriel Ferreira</a> at <a href="https://rettecnologia.org">RET Tecnologia</a> · Brazil 🇧🇷</sub>
</p>
