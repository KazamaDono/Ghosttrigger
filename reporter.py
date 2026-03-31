# reporter.py
"""
Enhanced Reporter with vulnerability classification and remediation advice
"""

from datetime import datetime
from typing import List, Dict, Any


class Reporter:
    def __init__(self, target_url: str, results: List[Dict[str, Any]]):
        self.target_url = target_url
        self.results = results

    def generate_markdown(self) -> str:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        lines = [
            "# GhostTrigger Security Assessment Report",
            "",
            f"**Target:** `{self.target_url}`",
            f"**Date:** {timestamp}",
            f"**Scanner Version:** GhostTrigger Professional v2.0",
            "",
            "---",
            "",
            "## Executive Summary",
            ""
        ]
        
        total = len(self.results)
        successful = sum(1 for r in self.results if r.get("success"))
        high_severity = sum(1 for r in self.results if r.get("candidate", {}).get("severity") == "high" and r.get("success"))
        medium_severity = sum(1 for r in self.results if r.get("candidate", {}).get("severity") == "medium" and r.get("success"))
        
        lines.append(f"Total candidates tested: **{total}**")
        lines.append(f"Successful exploitations: **{successful}**")
        lines.append(f"High severity findings: **{high_severity}**")
        lines.append(f"Medium severity findings: **{medium_severity}**")
        
        if successful > 0:
            lines.append("")
            lines.append("⚠️ **CRITICAL:** Authentication bypass vulnerabilities were detected. Immediate remediation is recommended.")
        else:
            lines.append("")
            lines.append("✅ No authentication bypass vulnerabilities were detected in automated testing.")
        
        lines.extend([
            "",
            "---",
            "",
            "## Detailed Findings",
            ""
        ])
        
        # Group by severity
        findings = []
        for r in self.results:
            if r.get("success"):
                findings.append(r)
        
        if findings:
            lines.append("### Vulnerabilities Found")
            lines.append("")
            lines.append("| Severity | Type | Description | Exploit |")
            lines.append("|----------|------|-------------|---------|")
            
            for r in findings:
                cand = r.get("candidate", {})
                severity = cand.get("severity", "unknown").upper()
                severity_icon = {
                    "HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵"
                }.get(severity, "⚪")
                
                cand_type = cand.get("type", "unknown").upper()
                description = cand.get("exploit_description", "No description")[:60]
                exploit = cand.get("exploit_js", "N/A")[:50] + "..."
                
                lines.append(f"| {severity_icon} {severity} | {cand_type} | {description} | `{exploit}` |")
            
            lines.append("")
            lines.append("### Detailed Exploit Information")
            lines.append("")
            
            for idx, r in enumerate(findings, 1):
                cand = r.get("candidate", {})
                lines.append(f"#### Finding {idx}: {cand.get('type', 'unknown').upper()}")
                lines.append("")
                lines.append(f"- **Severity:** {cand.get('severity', 'unknown').upper()}")
                lines.append(f"- **Source:** {cand.get('source', 'N/A')}")
                lines.append(f"- **Description:** {cand.get('exploit_description', 'No description')}")
                lines.append("")
                lines.append("**Exploit Code:**")
                lines.append("```javascript")
                lines.append(cand.get('exploit_js', '// No exploit generated'))
                lines.append("```")
                lines.append("")
                
                # Add remediation advice
                lines.append("**Remediation Advice:**")
                if cand.get("type") == "jwt_token":
                    lines.append("- Use strong signing algorithms (RS256, ES256) instead of HS256")
                    lines.append("- Never accept 'alg: none' tokens")
                    lines.append("- Implement proper token expiration and validation")
                    lines.append("- Use short-lived tokens with refresh mechanism")
                elif cand.get("type") == "idor":
                    lines.append("- Implement proper access control checks on every request")
                    lines.append("- Use UUIDs instead of sequential IDs")
                    lines.append("- Never trust client-side input for authorization")
                elif cand.get("type") == "graphql_endpoint":
                    lines.append("- Disable GraphQL introspection in production")
                    lines.append("- Implement depth limiting and query cost analysis")
                    lines.append("- Use persisted queries or allow-lists")
                elif cand.get("type") == "nosql_injection":
                    lines.append("- Sanitize and validate all user inputs")
                    lines.append("- Use parameterized queries or ORM with built-in protection")
                    lines.append("- Implement proper error handling")
                else:
                    lines.append("- Review and fix the identified vulnerability")
                    lines.append("- Implement proper authentication and authorization")
                    lines.append("- Conduct a full security audit")
                
                lines.append("")
                lines.append("---")
                lines.append("")
        else:
            lines.append("### No Vulnerabilities Found")
            lines.append("")
            lines.append("The automated scan did not detect any authentication bypass vulnerabilities.")
            lines.append("However, manual testing is still recommended for complex business logic flaws.")
        
        lines.extend([
            "",
            "## Methodology",
            "",
            "GhostTrigger performed the following tests:",
            "",
            "1. **JWT Token Analysis** - Testing for alg:none, weak signatures, claim injection",
            "2. **IDOR Detection** - Testing for insecure direct object references",
            "3. **Role Header Injection** - Testing privilege escalation via custom headers",
            "4. **GraphQL Introspection** - Attempting to extract schema and sensitive data",
            "5. **NoSQL Injection** - Testing login bypass with MongoDB operators",
            "6. **SSRF Detection** - Testing for server-side request forgery",
            "7. **Path Traversal** - Testing for directory traversal vulnerabilities",
            "8. **Legacy ASP.NET Checks** - Testing for __doPostBack and commented elements",
            "",
            "---",
            "",
            "## Disclaimer",
            "",
            "This report was generated by an automated tool and may contain false positives or false negatives.",
            "Manual verification of all findings is strongly recommended before taking remediation action.",
            "",
            "---",
            "",
            f"*Report generated by GhostTrigger Professional v2.0 on {timestamp}*"
        ])
        
        return "\n".join(lines)

    def save(self, filename: str):
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.generate_markdown())
        print(f"[+] Report saved to {filename}")