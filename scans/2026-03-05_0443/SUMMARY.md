# 🛡️ Security Reconnaissance Summary

**Scan Date:** $(date '+%Y-%m-%d %H:%M:%S UTC')  
**Workflow Run:** #48  
**Trigger:** schedule

---

## 📊 Statistics

| Metric | Count |
|--------|------:|
| Domains Scanned | ${DOMAINS_SCANNED:-0} |
| Screenshots | ${SCREENSHOTS_TAKEN:-0} |
| JS Files Analyzed | ${JS_FILES_ANALYZED:-0} |
| High-Priority Patterns | ${HIGH_PRIORITY_FINDINGS:-0} |
| Vulnerabilities | ${VULNERABILITIES_FOUND:-0} |
| **Total Issues** | **${TOTAL_ISSUES:-0}** |

## 🎯 Scanned Domains

$(cat tmp/selected.txt 2>/dev/null | nl -w2 -s'. ' || echo "No domains")

## 🔍 Results Summary

$(if [[ "${TOTAL_ISSUES:-0}" -gt 0 ]]; then
  echo "⚠️ **${TOTAL_ISSUES} potential security issue(s) detected**"
  echo ""
  [[ "${HIGH_PRIORITY_FINDINGS:-0}" -gt 0 ]] && echo "- ${HIGH_PRIORITY_FINDINGS} high-priority JS patterns"
  [[ "${VULNERABILITIES_FOUND:-0}" -gt 0 ]] && echo "- ${VULNERABILITIES_FOUND} vulnerabilities"
else
  echo "✅ **No security issues detected**"
  echo ""
  echo "All scanned assets passed security checks."
fi)

## 📝 Generated Reports

$(ls final_reports/REPORT_*.md 2>/dev/null | sed 's/final_reports\//- /' || echo "- None")

---

**Repository:** Rubics213/cuben  
**Branch:** master  
**Commit:** ${GITHUB_SHA:0:7}
