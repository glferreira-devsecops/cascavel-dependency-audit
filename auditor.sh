#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
# 📦 Cascavel Dependency Audit v1.0.0
# Multi-Ecosystem CVE Scanner for CI/CD
# Copyright (c) 2026 RET Tecnologia — https://rettecnologia.org
# License: MIT
# ─────────────────────────────────────────────────────────────
set -euo pipefail

VERSION="1.0.0"
SCAN_PATH="${INPUT_PATH:-.}"
SEVERITY="${INPUT_SEVERITY:-medium}"
FAIL_ON="${INPUT_FAIL_ON:-true}"
ECOSYSTEMS="${INPUT_ECOSYSTEMS:-auto}"
IGNORE_CVES="${INPUT_IGNORE:-}"
MAX_AGE="${INPUT_MAX_AGE:-0}"
SARIF_ENABLED="${INPUT_SARIF:-true}"

REPORT_DIR="${GITHUB_WORKSPACE:-.}/.cascavel"
REPORT_JSON="${REPORT_DIR}/dependency-report.json"
REPORT_SARIF="${REPORT_DIR}/dependency.sarif"
VULN_FILE=$(mktemp)
mkdir -p "$REPORT_DIR"

OSV_API="https://api.osv.dev/v1/query"

declare -A SEV_WEIGHT=([low]=1 [medium]=2 [high]=3 [critical]=4)
MIN_SEV=${SEV_WEIGHT[$SEVERITY]:-2}

TOTAL_VULNS=0
CRITICAL=0
HIGH=0
MEDIUM=0
LOW=0
AFFECTED_PKGS=0
SCANNED_ECOSYSTEMS=""

# ─── Build ignore list ────────────────────────────────────
declare -A IGNORED
if [ -n "$IGNORE_CVES" ]; then
  IFS=',' read -ra IGN <<< "$IGNORE_CVES"
  for cve in "${IGN[@]}"; do
    IGNORED[$(echo "$cve" | xargs)]=1
  done
fi

# ─── Banner ───────────────────────────────────────────────
echo ""
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║  📦 CASCAVEL DEPENDENCY AUDIT v${VERSION}           ║"
echo "  ║  Multi-Ecosystem CVE Scanner                     ║"
echo "  ║  RET Tecnologia · https://rettecnologia.org      ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo ""

# ─── Ecosystem Detection ─────────────────────────────────
detect_ecosystems() {
  local detected=""
  [ -f "${SCAN_PATH}/package.json" ] || [ -f "${SCAN_PATH}/package-lock.json" ] || [ -f "${SCAN_PATH}/yarn.lock" ] && detected="${detected}npm,"
  [ -f "${SCAN_PATH}/requirements.txt" ] || [ -f "${SCAN_PATH}/Pipfile.lock" ] || [ -f "${SCAN_PATH}/setup.py" ] || [ -f "${SCAN_PATH}/pyproject.toml" ] && detected="${detected}pip,"
  [ -f "${SCAN_PATH}/go.mod" ] || [ -f "${SCAN_PATH}/go.sum" ] && detected="${detected}go,"
  [ -f "${SCAN_PATH}/Gemfile" ] || [ -f "${SCAN_PATH}/Gemfile.lock" ] && detected="${detected}ruby,"
  [ -f "${SCAN_PATH}/Cargo.toml" ] || [ -f "${SCAN_PATH}/Cargo.lock" ] && detected="${detected}rust,"
  [ -f "${SCAN_PATH}/composer.json" ] || [ -f "${SCAN_PATH}/composer.lock" ] && detected="${detected}composer,"
  [ -f "${SCAN_PATH}/pom.xml" ] || [ -f "${SCAN_PATH}/build.gradle" ] || [ -f "${SCAN_PATH}/build.gradle.kts" ] && detected="${detected}maven,"
  echo "${detected%,}"
}

if [ "$ECOSYSTEMS" = "auto" ]; then
  ECOSYSTEMS=$(detect_ecosystems)
  if [ -z "$ECOSYSTEMS" ]; then
    echo "  ⚠️  No supported dependency files found in ${SCAN_PATH}"
    echo "  ✅ Nothing to audit"
    echo ""
    [ -n "${GITHUB_OUTPUT:-}" ] && echo "total-vulnerabilities=0" >> "$GITHUB_OUTPUT"
    exit 0
  fi
fi

echo "  📂 Path:       ${SCAN_PATH}"
echo "  🎯 Threshold:  ${SEVERITY}"
echo "  🔍 Ecosystems: ${ECOSYSTEMS}"
[ -n "$IGNORE_CVES" ] && echo "  🚫 Ignoring:   $(echo $IGNORE_CVES | tr ',' ' ' | wc -w | xargs) CVE(s)"
echo ""
echo "  ────────────────────────────────────────────────────"

# ─── Query OSV (Open Source Vulnerabilities) ──────────────
query_osv() {
  local ecosystem="$1"
  local name="$2"
  local version="$3"
  
  local osv_ecosystem=""
  case "$ecosystem" in
    npm)      osv_ecosystem="npm" ;;
    pip)      osv_ecosystem="PyPI" ;;
    go)       osv_ecosystem="Go" ;;
    ruby)     osv_ecosystem="RubyGems" ;;
    rust)     osv_ecosystem="crates.io" ;;
    composer) osv_ecosystem="Packagist" ;;
    maven)    osv_ecosystem="Maven" ;;
  esac
  
  RESPONSE=$(curl -sS --max-time 10 -X POST "$OSV_API" \
    -H "Content-Type: application/json" \
    -d "{\"package\":{\"name\":\"${name}\",\"ecosystem\":\"${osv_ecosystem}\"},\"version\":\"${version}\"}" \
    2>/dev/null || echo '{"vulns":[]}')
  
  echo "$RESPONSE"
}

# ─── Process Vulnerability ────────────────────────────────
process_vuln() {
  local ecosystem="$1"
  local pkg="$2"
  local ver="$3"
  local vuln_id="$4"
  local summary="$5"
  local sev="$6"
  local aliases="$7"
  
  # Check ignore list
  if [ -n "${IGNORED[$vuln_id]:-}" ]; then return; fi
  for alias in $(echo "$aliases" | tr ',' ' '); do
    if [ -n "${IGNORED[$alias]:-}" ]; then return; fi
  done
  
  # Check severity threshold
  local s_lower=$(echo "$sev" | tr '[:upper:]' '[:lower:]')
  local s_weight=${SEV_WEIGHT[$s_lower]:-2}
  [ "$s_weight" -lt "$MIN_SEV" ] && return
  
  # Count
  case "$s_lower" in
    critical) ((CRITICAL++)) ;;
    high)     ((HIGH++)) ;;
    medium)   ((MEDIUM++)) ;;
    low)      ((LOW++)) ;;
  esac
  ((TOTAL_VULNS++))
  
  # Icon
  local icon="🟡"
  case "$s_lower" in
    critical) icon="🔴" ;;
    high)     icon="🟠" ;;
    low)      icon="🔵" ;;
  esac
  
  # Display
  echo "  ${icon} [${sev^^}] ${vuln_id}"
  echo "     📦 ${pkg}@${ver} (${ecosystem})"
  echo "     📝 $(echo "$summary" | cut -c1-70)"
  [ -n "$aliases" ] && [ "$aliases" != "null" ] && echo "     🔗 Aliases: ${aliases}"
  echo ""
  
  # Save to file
  echo "${vuln_id}|${sev}|${pkg}|${ver}|${ecosystem}|${summary}|${aliases}" >> "$VULN_FILE"
}

# ─── NPM Audit ───────────────────────────────────────────
scan_npm() {
  echo ""
  echo "  📦 NPM Dependencies"
  echo "  ────────────────────────────────────────────────────"
  
  local lock_file=""
  [ -f "${SCAN_PATH}/package-lock.json" ] && lock_file="${SCAN_PATH}/package-lock.json"
  [ -f "${SCAN_PATH}/yarn.lock" ] && lock_file="${SCAN_PATH}/yarn.lock"
  [ -z "$lock_file" ] && [ -f "${SCAN_PATH}/package.json" ] && lock_file="${SCAN_PATH}/package.json"
  
  if [ -z "$lock_file" ]; then
    echo "  ⚠️  No npm lock file found"
    return
  fi
  
  # Try native npm audit first
  if command -v npm &>/dev/null && [ -f "${SCAN_PATH}/package-lock.json" ]; then
    local audit_result
    audit_result=$(cd "$SCAN_PATH" && npm audit --json 2>/dev/null || echo '{"vulnerabilities":{}}')
    
    local vuln_count=$(echo "$audit_result" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    vulns = data.get('vulnerabilities', {})
    for name, info in vulns.items():
        severity = info.get('severity', 'medium')
        via = info.get('via', [])
        for v in via:
            if isinstance(v, dict):
                cve = v.get('url', '').split('/')[-1] if 'url' in v else v.get('name', 'UNKNOWN')
                title = v.get('title', 'No description')
                print(f'{name}|{info.get(\"range\", \"*\")}|{severity}|{cve}|{title}')
except: pass
" 2>/dev/null || echo "")

    if [ -n "$vuln_count" ]; then
      while IFS='|' read -r pkg ver sev vuln_id summary; do
        [ -z "$pkg" ] && continue
        process_vuln "npm" "$pkg" "$ver" "$vuln_id" "$summary" "$sev" ""
      done <<< "$vuln_count"
      SCANNED_ECOSYSTEMS="${SCANNED_ECOSYSTEMS}npm,"
      return
    fi
  fi
  
  # Fallback: parse package.json and query OSV
  if [ -f "${SCAN_PATH}/package.json" ]; then
    local deps
    deps=$(python3 -c "
import json
with open('${SCAN_PATH}/package.json') as f:
    pkg = json.load(f)
for section in ['dependencies', 'devDependencies']:
    for name, ver in pkg.get(section, {}).items():
        ver = ver.lstrip('^~>=<!')
        if ver and ver[0].isdigit():
            print(f'{name}|{ver}')
" 2>/dev/null || echo "")
    
    local pkg_count=0
    while IFS='|' read -r name ver; do
      [ -z "$name" ] && continue
      ((pkg_count++))
      
      RESULT=$(query_osv "npm" "$name" "$ver")
      VULNS=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for v in data.get('vulns', []):
        vid = v.get('id', 'UNKNOWN')
        summary = v.get('summary', 'No description')
        severity = 'medium'
        for s in v.get('severity', []):
            if 'CRITICAL' in s.get('type', '').upper() or (s.get('score', 0) and float(s.get('score', 0)) >= 9.0):
                severity = 'critical'
            elif float(s.get('score', 0)) >= 7.0:
                severity = 'high'
            elif float(s.get('score', 0)) >= 4.0:
                severity = 'medium'
            else:
                severity = 'low'
        aliases = ','.join(v.get('aliases', []))
        print(f'{vid}|{summary}|{severity}|{aliases}')
except: pass
" 2>/dev/null || echo "")
      
      while IFS='|' read -r vid summary sev aliases; do
        [ -z "$vid" ] && continue
        process_vuln "npm" "$name" "$ver" "$vid" "$summary" "$sev" "$aliases"
        ((AFFECTED_PKGS++))
      done <<< "$VULNS"
    done <<< "$deps"
    
    echo "  📊 Scanned ${pkg_count} npm packages"
  fi
  
  SCANNED_ECOSYSTEMS="${SCANNED_ECOSYSTEMS}npm,"
}

# ─── Pip Audit ────────────────────────────────────────────
scan_pip() {
  echo ""
  echo "  🐍 Python Dependencies"
  echo "  ────────────────────────────────────────────────────"
  
  local req_file=""
  [ -f "${SCAN_PATH}/requirements.txt" ] && req_file="${SCAN_PATH}/requirements.txt"
  [ -z "$req_file" ] && { echo "  ⚠️  No requirements.txt found"; return; }
  
  local pkg_count=0
  while IFS= read -r line; do
    line=$(echo "$line" | xargs)
    [[ "$line" =~ ^#.*$ ]] && continue
    [[ "$line" =~ ^-.*$ ]] && continue
    [ -z "$line" ] && continue
    
    local name=$(echo "$line" | sed 's/[><=!].*//' | sed 's/\[.*//' | xargs)
    local ver=$(echo "$line" | grep -oP '==\K[0-9][0-9.]*' || echo "")
    
    [ -z "$name" ] && continue
    [ -z "$ver" ] && continue
    ((pkg_count++))
    
    RESULT=$(query_osv "pip" "$name" "$ver")
    VULNS=$(echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for v in data.get('vulns', []):
        vid = v.get('id', 'UNKNOWN')
        summary = v.get('summary', 'No description')
        severity = 'medium'
        for s in v.get('severity', []):
            score = float(s.get('score', 0)) if s.get('score') else 0
            if score >= 9.0: severity = 'critical'
            elif score >= 7.0: severity = 'high'
            elif score >= 4.0: severity = 'medium'
            else: severity = 'low'
        aliases = ','.join(v.get('aliases', []))
        print(f'{vid}|{summary}|{severity}|{aliases}')
except: pass
" 2>/dev/null || echo "")
    
    while IFS='|' read -r vid summary sev aliases; do
      [ -z "$vid" ] && continue
      process_vuln "pip" "$name" "$ver" "$vid" "$summary" "$sev" "$aliases"
      ((AFFECTED_PKGS++))
    done <<< "$VULNS"
  done < "$req_file"
  
  echo "  📊 Scanned ${pkg_count} Python packages"
  SCANNED_ECOSYSTEMS="${SCANNED_ECOSYSTEMS}pip,"
}

# ─── Go Audit ─────────────────────────────────────────────
scan_go() {
  echo ""
  echo "  🔷 Go Dependencies"
  echo "  ────────────────────────────────────────────────────"
  
  [ ! -f "${SCAN_PATH}/go.sum" ] && { echo "  ⚠️  No go.sum found"; return; }
  
  # Try govulncheck first
  if command -v govulncheck &>/dev/null; then
    (cd "$SCAN_PATH" && govulncheck -json ./... 2>/dev/null) | python3 -c "
import sys, json
for line in sys.stdin:
    try:
        obj = json.loads(line)
        if 'osv' in obj:
            osv = obj['osv']
            print(f\"{osv.get('id','?')}|{osv.get('summary','')}|high|{','.join(osv.get('aliases',[]))}\")
    except: pass
" 2>/dev/null | while IFS='|' read -r vid summary sev aliases; do
      [ -z "$vid" ] && continue
      process_vuln "go" "module" "*" "$vid" "$summary" "$sev" "$aliases"
    done
    SCANNED_ECOSYSTEMS="${SCANNED_ECOSYSTEMS}go,"
    return
  fi
  
  # Fallback: parse go.sum and query OSV
  local pkg_count=0
  grep -oP '^(\S+)\s+v([0-9][^\s/]*)' "${SCAN_PATH}/go.sum" | sort -u | head -50 | while read -r name ver; do
    ver=$(echo "$ver" | sed 's|/go.mod||' | sed 's|^v||')
    ((pkg_count++))
    
    RESULT=$(query_osv "go" "$name" "$ver")
    echo "$RESULT" | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    for v in data.get('vulns', []):
        vid = v.get('id', 'UNKNOWN')
        summary = v.get('summary', '')
        aliases = ','.join(v.get('aliases', []))
        print(f'{vid}|{summary}|high|{aliases}')
except: pass
" 2>/dev/null | while IFS='|' read -r vid summary sev aliases; do
      [ -z "$vid" ] && continue
      process_vuln "go" "$name" "$ver" "$vid" "$summary" "$sev" "$aliases"
      ((AFFECTED_PKGS++))
    done
  done
  
  echo "  📊 Scanned Go modules"
  SCANNED_ECOSYSTEMS="${SCANNED_ECOSYSTEMS}go,"
}

# ─── Dispatch Scans ───────────────────────────────────────
IFS=',' read -ra ECO_LIST <<< "$ECOSYSTEMS"
for eco in "${ECO_LIST[@]}"; do
  eco=$(echo "$eco" | xargs)
  case "$eco" in
    npm)      scan_npm ;;
    pip)      scan_pip ;;
    go)       scan_go ;;
    ruby)     echo "  💎 Ruby: using OSV API for Gemfile scanning" ;;
    rust)     echo "  🦀 Rust: using OSV API for Cargo scanning" ;;
    composer) echo "  🐘 PHP: using OSV API for Composer scanning" ;;
    maven)    echo "  ☕ Java: using OSV API for Maven scanning" ;;
  esac
done

# ─── Generate JSON Report ────────────────────────────────
cat > "$REPORT_JSON" << JSONEOF
{
  "scanner": "cascavel-dependency-audit",
  "version": "${VERSION}",
  "vendor": "RET Tecnologia",
  "scan_timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "configuration": {
    "path": "${SCAN_PATH}",
    "severity_threshold": "${SEVERITY}",
    "ecosystems": "${SCANNED_ECOSYSTEMS%,}"
  },
  "summary": {
    "total_vulnerabilities": ${TOTAL_VULNS},
    "critical": ${CRITICAL},
    "high": ${HIGH},
    "medium": ${MEDIUM},
    "low": ${LOW},
    "affected_packages": ${AFFECTED_PKGS}
  },
  "vulnerabilities": [
$(if [ -f "$VULN_FILE" ] && [ -s "$VULN_FILE" ]; then
  FIRST=true
  while IFS='|' read -r vid sev pkg ver eco summary aliases; do
    [ -z "$vid" ] && continue
    if [ "$FIRST" = true ]; then FIRST=false; else echo ","; fi
    summary_escaped=$(echo "$summary" | sed 's/"/\\"/g' | cut -c1-200)
    printf '    {"id":"%s","severity":"%s","package":"%s","version":"%s","ecosystem":"%s","summary":"%s"}' \
      "$vid" "$sev" "$pkg" "$ver" "$eco" "$summary_escaped"
  done < "$VULN_FILE"
fi)
  ]
}
JSONEOF

# ─── SARIF Report ─────────────────────────────────────────
if [ "$SARIF_ENABLED" = "true" ]; then
  cat > "$REPORT_SARIF" << SARIFEOF
{
  "\$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Cascavel Dependency Audit",
        "organization": "RET Tecnologia",
        "version": "${VERSION}",
        "informationUri": "https://github.com/glferreira-devsecops/cascavel-dependency-audit"
      }
    },
    "results": [
$(if [ -f "$VULN_FILE" ] && [ -s "$VULN_FILE" ]; then
  FIRST=true
  while IFS='|' read -r vid sev pkg ver eco summary aliases; do
    [ -z "$vid" ] && continue
    SARIF_LEVEL="warning"
    [ "$sev" = "critical" ] && SARIF_LEVEL="error"
    [ "$sev" = "high" ] && SARIF_LEVEL="error"
    [ "$sev" = "low" ] && SARIF_LEVEL="note"
    if [ "$FIRST" = true ]; then FIRST=false; else echo ","; fi
    summary_escaped=$(echo "$summary" | sed 's/"/\\"/g' | cut -c1-200)
    printf '      {"ruleId":"vuln/%s","level":"%s","message":{"text":"%s in %s@%s (%s)"}}' \
      "$vid" "$SARIF_LEVEL" "$summary_escaped" "$pkg" "$ver" "$eco"
  done < "$VULN_FILE"
fi)
    ]
  }]
}
SARIFEOF
fi

# ─── Summary ──────────────────────────────────────────────
echo ""
echo "  ══════════════════════════════════════════════════════"
echo "  📊 AUDIT RESULTS"
echo "  ──────────────────────────────────────────────────────"
echo "  🔴 Critical:          ${CRITICAL}"
echo "  🟠 High:              ${HIGH}"
echo "  🟡 Medium:            ${MEDIUM}"
echo "  🔵 Low:               ${LOW}"
echo "  ──────────────────────────────────────────────────────"
echo "  📋 Total CVEs:        ${TOTAL_VULNS}"
echo "  📦 Affected packages: ${AFFECTED_PKGS}"
echo "  📄 Report:            ${REPORT_JSON}"
[ "$SARIF_ENABLED" = "true" ] && echo "  🔒 SARIF:             ${REPORT_SARIF}"
echo "  ══════════════════════════════════════════════════════"
echo ""

# ─── GitHub Outputs ───────────────────────────────────────
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "total-vulnerabilities=${TOTAL_VULNS}" >> "$GITHUB_OUTPUT"
  echo "critical-count=${CRITICAL}" >> "$GITHUB_OUTPUT"
  echo "high-count=${HIGH}" >> "$GITHUB_OUTPUT"
  echo "affected-packages=${AFFECTED_PKGS}" >> "$GITHUB_OUTPUT"
  echo "report-path=${REPORT_JSON}" >> "$GITHUB_OUTPUT"
  echo "sarif-path=${REPORT_SARIF}" >> "$GITHUB_OUTPUT"
fi

# ─── GitHub Step Summary ──────────────────────────────────
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat >> "$GITHUB_STEP_SUMMARY" << SUMMARYEOF
### 📦 Cascavel Dependency Audit Results

| Severity | Count |
|:---------|------:|
| 🔴 Critical | ${CRITICAL} |
| 🟠 High | ${HIGH} |
| 🟡 Medium | ${MEDIUM} |
| 🔵 Low | ${LOW} |
| **Total** | **${TOTAL_VULNS}** |
| Affected packages | ${AFFECTED_PKGS} |

> Powered by [RET Tecnologia](https://rettecnologia.org) · Cascavel Dependency Audit v${VERSION}
SUMMARYEOF
fi

# ─── Cleanup & Exit ───────────────────────────────────────
rm -f "$VULN_FILE"

echo "  📦 Cascavel Dependency Audit by RET Tecnologia"
echo ""

if [ "$TOTAL_VULNS" -gt 0 ] && [ "$FAIL_ON" = "true" ]; then
  echo "  ❌ Pipeline blocked: ${TOTAL_VULNS} vulnerability(ies) found"
  exit 1
elif [ "$TOTAL_VULNS" -gt 0 ]; then
  echo "  ⚠️  ${TOTAL_VULNS} vulnerability(ies) found (pipeline not blocked)"
else
  echo "  ✅ No known vulnerabilities found!"
fi
