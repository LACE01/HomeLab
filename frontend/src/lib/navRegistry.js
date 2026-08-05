// One list of every place you can navigate to, and the single source of truth
// for both the sidebar and the Cmd-K command palette.
//
// WHY A REGISTRY
//
// The sidebar had the full nav list hard-coded in JSX. Adding a command palette
// meant either duplicating that list (which drifts -- a page added to one and not
// the other) or deriving both from one place. This is that place. A test asserts
// every route the sidebar links to appears here, so they cannot silently diverge.
//
// `keywords` exist so the palette finds a page by what people CALL it, not only by
// its label: someone typing "edr" should find Directory/Defender, "dmarc" should
// find Email Authentication, "cve" should find Findings. A jump-to that only
// matches the visible label is barely faster than reading the sidebar.

export const NAV = [
  // group, label, path, keywords
  { group: "Overview", label: "Dashboard", to: "/", keywords: "home overview kpi metrics" },
  { group: "Overview", label: "SOC Overview", to: "/soc", keywords: "soc operations center live" },
  { group: "Overview", label: "Team Dashboards", to: "/operational", keywords: "team operational per-team" },

  { group: "Vulnerability Management", label: "Findings", to: "/findings", keywords: "vulnerabilities cve qid vulns issues" },
  { group: "Vulnerability Management", label: "Attack Paths", to: "/attack-paths", keywords: "graph lateral movement crown jewel chokepoint" },
  { group: "Vulnerability Management", label: "Exposure", to: "/exposure", keywords: "internet facing external exposed" },
  { group: "Vulnerability Management", label: "TLS Certificates", to: "/admin/tls-certs", keywords: "ssl cert expiry certificate https" },
  { group: "Vulnerability Management", label: "Email Authentication", to: "/admin/email-auth", keywords: "spf dkim dmarc email spoofing" },
  { group: "Vulnerability Management", label: "End-of-Life Software", to: "/admin/eol-tracking", keywords: "eol eos obsolete unsupported end of life" },
  { group: "Vulnerability Management", label: "Container Image Scanning", to: "/admin/container-scan", keywords: "docker trivy image container sbom" },
  { group: "Vulnerability Management", label: "Secrets Scanning", to: "/admin/secrets-scan", keywords: "secrets credentials leak git repo detect-secrets" },
  { group: "Vulnerability Management", label: "Attack Surface", to: "/easm", keywords: "easm subdomain discovery crt.sh external" },
  { group: "Vulnerability Management", label: "Tickets", to: "/tickets", keywords: "remediation jira servicenow work" },
  { group: "Vulnerability Management", label: "Exceptions", to: "/exceptions", keywords: "risk accepted exception waiver" },
  { group: "Vulnerability Management", label: "Playbooks", to: "/admin/playbooks", keywords: "runbook procedure response steps" },
  { group: "Vulnerability Management", label: "Automation", to: "/automation", keywords: "rules automation soar workflow" },

  { group: "Detection & Response", label: "Security Alerts", to: "/alerts", keywords: "alerts events detections siem" },
  { group: "Detection & Response", label: "Threat Intel Watchlist", to: "/admin/threat-intel", keywords: "ioc indicator threatfox watchlist opencti" },
  { group: "Detection & Response", label: "Albert Network Monitoring", to: "/admin/albert", keywords: "albert ids ms-isac network sensor" },
  { group: "Detection & Response", label: "Triage Wizard", to: "/ir/wizard", keywords: "incident triage wizard classify" },
  { group: "Detection & Response", label: "IR Cases", to: "/ir/cases", keywords: "incident response case investigation" },
  { group: "Detection & Response", label: "IR Setup", to: "/admin/ir-setup", keywords: "incident response configuration playbook" },

  { group: "Asset Inventory", label: "Assets", to: "/assets", keywords: "hosts devices machines inventory endpoints" },
  { group: "Asset Inventory", label: "Products", to: "/products", keywords: "software applications products services" },
  { group: "Asset Inventory", label: "Engagements", to: "/engagements", keywords: "scans runs imports scan history" },
  { group: "Asset Inventory", label: "Directory", to: "/directory", keywords: "users groups entra edr defender intune identity" },

  { group: "Scanning & Integrations", label: "Connectors", to: "/integrations", keywords: "integrations connectors api qualys nessus defender" },
  { group: "Scanning & Integrations", label: "Import Jobs", to: "/imports", keywords: "import upload csv xlsx jobs" },
  { group: "Scanning & Integrations", label: "Web Scan Uploads", to: "/admin/web-scans", keywords: "web scan upload" },
  { group: "Scanning & Integrations", label: "Nmap Scan Uploads", to: "/admin/nmap-scans", keywords: "nmap port scan network" },
  { group: "Scanning & Integrations", label: "Web App Scans (Nikto)", to: "/admin/nikto-scans", keywords: "nikto web app scanner" },
  { group: "Scanning & Integrations", label: "Recon & OSINT", to: "/admin/recon-osint", keywords: "recon-ng osint reconnaissance" },
  { group: "Scanning & Integrations", label: "CTI & OSINT Hub", to: "/admin/cti", keywords: "cti threat intel opencti articles feeds osint" },
  { group: "Scanning & Integrations", label: "Attack Telemetry", to: "/attack-telemetry", keywords: "cloudflare telemetry waf edge traffic" },
  { group: "Scanning & Integrations", label: "Criticality Scoring", to: "/admin/criticality-scoring", keywords: "criticality asset importance scoring" },
  { group: "Scanning & Integrations", label: "SBOM / Dependencies", to: "/admin/sbom", keywords: "sbom dependencies cyclonedx spdx components" },
  { group: "Scanning & Integrations", label: "YARA Scanning", to: "/admin/yara", keywords: "yara malware rules" },
  { group: "Scanning & Integrations", label: "Scan Schedule", to: "/admin/scan-schedule", keywords: "schedule cron scan timing" },
  { group: "Scanning & Integrations", label: "Splunk", to: "/admin/splunk", keywords: "splunk saved search siem" },
  { group: "Scanning & Integrations", label: "Wazuh", to: "/admin/wazuh", keywords: "wazuh indexer siem edr" },
  { group: "Scanning & Integrations", label: "Ticketing / SOAR", to: "/admin/ticketing", keywords: "jira servicenow soar webhook ticketing" },

  { group: "Reports & Compliance", label: "Reports", to: "/reports", keywords: "report export pdf docx executive" },
  { group: "Reports & Compliance", label: "Compliance", to: "/compliance", keywords: "soc2 iso27001 pci nist cis framework compliance" },
  { group: "Reports & Compliance", label: "Risk Register", to: "/risk-register", keywords: "risk register enterprise risk" },
  { group: "Reports & Compliance", label: "Security Reviews", to: "/security-reviews", keywords: "vendor review assessment questionnaire security review" },
  { group: "Reports & Compliance", label: "Threat Modeling", to: "/threat-modeling", keywords: "stride threat model dfd" },
  { group: "Reports & Compliance", label: "Vendor & Third-Party Risk", to: "/vendors", keywords: "vendor third party supplier tprm" },

  { group: "Administration", label: "Admin", to: "/admin", keywords: "administration settings" },
  { group: "Administration", label: "Settings", to: "/admin/settings", keywords: "settings preferences feature flags configuration" },
  { group: "Administration", label: "Users", to: "/admin/users", keywords: "users accounts people access" },
  { group: "Administration", label: "Teams", to: "/admin/teams", keywords: "teams groups org" },
  { group: "Administration", label: "Notifications", to: "/admin/notifications", keywords: "notifications email alerts digest" },
  { group: "Administration", label: "ChatOps", to: "/admin/chatops", keywords: "slack teams chatops chat" },
  { group: "Administration", label: "System Health", to: "/admin/health", keywords: "health status loops connectors observability uptime" },
  { group: "Administration", label: "Backups", to: "/admin/backups", keywords: "backup restore export database" },
  { group: "Administration", label: "Data Retention", to: "/admin/retention", keywords: "retention purge data lifecycle" },
  { group: "Administration", label: "Audit Log", to: "/admin/audit-log", keywords: "audit log activity history" },
  { group: "Administration", label: "Assignment Rules", to: "/admin/assignment-rules", keywords: "assignment ownership routing rules" },
  { group: "Administration", label: "Ownership Map", to: "/admin/ownership", keywords: "ownership team mapping" },
  { group: "Administration", label: "SLA Policies", to: "/admin/sla-policies", keywords: "sla policy due date deadline" },
  { group: "Administration", label: "Approval Routing", to: "/admin/approval-routing", keywords: "approval routing workflow authorization" },
  { group: "Administration", label: "Role Access", to: "/admin/rbac", keywords: "rbac role access permissions" },
];

// A page can be found by its label, its group, or any of its keywords. Ranking:
// an exact/prefix hit on the LABEL beats a keyword hit, so typing "find" surfaces
// Findings above pages that merely mention findings in their keywords.
export function searchNav(query, canAccess) {
  const q = (query || "").trim().toLowerCase();
  const visible = NAV.filter((n) => (canAccess ? canAccess(n.to) : true));
  if (!q) return visible.map((n) => ({ ...n, score: 0 }));

  const scored = [];
  for (const n of visible) {
    const label = n.label.toLowerCase();
    const hay = `${label} ${n.group.toLowerCase()} ${n.keywords || ""}`;
    let score = null;
    if (label === q) score = 100;
    else if (label.startsWith(q)) score = 80;
    else if (label.includes(q)) score = 60;
    else if ((n.keywords || "").split(/\s+/).some((k) => k === q)) score = 50;
    else if (hay.includes(q)) score = 30;
    else if (subsequence(q, label)) score = 15; // fuzzy: "atpth" -> "Attack Paths"
    if (score !== null) scored.push({ ...n, score });
  }
  scored.sort((a, b) => b.score - a.score || a.label.localeCompare(b.label));
  return scored;
}

// Does every character of `q` appear in `s`, in order? The cheap fuzzy match that
// makes a palette feel fast -- "scr" finds "Secrets Scanning".
function subsequence(q, s) {
  let i = 0;
  for (const c of s) {
    if (c === q[i]) i++;
    if (i === q.length) return true;
  }
  return i === q.length;
}
