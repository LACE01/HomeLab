// One list of every place you can navigate to -- the single source of truth for
// the sidebar AND the Cmd-K command palette (item 40).
//
// ITEM 40 -- IA overhaul. The sidebar was ~66 flat links in 7 groups, hard-coded
// in Sidebar.jsx and already drifting from this registry (Remediation Campaigns,
// Application Inventory and Geo-Forecast were missing from the palette). Now:
//   * 12 top-level SECTIONS, two levels max (section -> page)
//   * the Sidebar renders FROM this file, so the two can no longer diverge
//   * visibility is role-gated per page (canAccess); a section with no
//     accessible pages disappears entirely
// `keywords` let the palette find a page by what people CALL it ("dmarc" ->
// Email Authentication, "cve" -> Findings), not only by its label.
import {
  Archive, At, Bell, Binoculars, BookOpen, Broadcast, Buildings, CalendarBlank, CalendarX, Certificate, ChartLineUp, ClipboardText, Cube, Database, FileArrowDown, FirstAidKit, Flask, FlowArrow, Gauge, GearSix, Globe, HardDrive, HardDrives, Heartbeat, Key, Lightning, ListChecks, LockKey, MagnifyingGlass, Notepad, Package, PlugsConnected, Robot, ShareNetwork, ShieldCheck, Siren, SlackLogo, SlidersHorizontal, Stack, Target, Ticket, UsersThree, Virus, Warning, WebhooksLogo,
} from "@phosphor-icons/react";

export const SECTIONS = [
  { key: "dashboards", label: "Dashboards", icon: ChartLineUp, items: [
    { label: "Dashboard", to: "/", icon: ChartLineUp, testid: "nav-dashboard", keywords: "home overview kpi metrics" },
    { label: "SOC Overview", to: "/soc", icon: Gauge, testid: "nav-soc", keywords: "soc operations center live" },
    { label: "Team Dashboards", to: "/operational", icon: Lightning, testid: "nav-operational", keywords: "team operational per-team" },
  ] },
  { key: "findings", label: "Findings", icon: ListChecks, items: [
    { label: "Findings", to: "/findings", icon: ListChecks, testid: "nav-findings", keywords: "vulnerabilities cve qid vulns issues" },
    { label: "Attack Paths", to: "/attack-paths", icon: ShareNetwork, testid: "nav-attack-paths", keywords: "graph lateral movement crown jewel chokepoint" },
    { label: "Exposure", to: "/exposure", icon: Globe, testid: "nav-exposure", keywords: "internet facing external exposed" },
  ] },
  { key: "remediation", label: "Remediation", icon: Target, items: [
    { label: "Remediation Campaigns", to: "/remediation-campaigns", icon: Target, testid: "nav-remediation", keywords: "campaign patch tracker remediation burndown" },
    { label: "Tickets", to: "/tickets", icon: Ticket, testid: "nav-tickets", keywords: "remediation jira servicenow work" },
    { label: "Exceptions", to: "/exceptions", icon: ShieldCheck, testid: "nav-exceptions", keywords: "risk accepted exception waiver" },
    { label: "Automation", to: "/automation", icon: Robot, testid: "nav-automation", keywords: "rules automation soar workflow" },
    { label: "Playbooks", to: "/admin/playbooks", icon: BookOpen, testid: "nav-playbooks", keywords: "runbook procedure response steps" },
  ] },
  { key: "surface", label: "Attack Surface", icon: Globe, items: [
    { label: "Attack Surface", to: "/easm", icon: MagnifyingGlass, testid: "nav-easm", keywords: "easm subdomain discovery crt.sh external" },
    { label: "TLS Certificates", to: "/admin/tls-certs", icon: Certificate, testid: "nav-tls-certs", keywords: "ssl cert expiry certificate https" },
    { label: "Email Authentication", to: "/admin/email-auth", icon: At, testid: "nav-email-auth", keywords: "spf dkim dmarc email spoofing" },
    { label: "Attack Telemetry", to: "/attack-telemetry", icon: Lightning, testid: "nav-attack-telemetry", keywords: "cloudflare telemetry waf edge traffic" },
    { label: "Recon & OSINT", to: "/admin/recon-osint", icon: MagnifyingGlass, testid: "nav-recon-osint", keywords: "recon-ng osint reconnaissance" },
  ] },
  { key: "detection", label: "Detection & Response", icon: Siren, items: [
    { label: "Security Alerts", to: "/alerts", icon: Siren, testid: "nav-alerts", keywords: "alerts events detections siem" },
    { label: "IR Cases", to: "/ir/cases", icon: Siren, testid: "nav-ir-cases", keywords: "incident response case investigation" },
    { label: "Triage Wizard", to: "/ir/wizard", icon: FirstAidKit, testid: "nav-ir-wizard", keywords: "incident triage wizard classify" },
    { label: "Albert Network Monitoring", to: "/admin/albert", icon: Broadcast, testid: "nav-albert", keywords: "albert ids ms-isac network sensor" },
    { label: "IR Setup", to: "/admin/ir-setup", icon: SlidersHorizontal, testid: "nav-ir-setup", keywords: "incident response configuration playbook" },
  ] },
  { key: "intel", label: "Threat Intelligence", icon: Virus, items: [
    { label: "CTI & OSINT Hub", to: "/admin/cti", icon: Virus, testid: "nav-cti-hub", keywords: "cti threat intel opencti articles feeds osint" },
    { label: "Threat Intel Watchlist", to: "/admin/threat-intel", icon: Binoculars, testid: "nav-threat-intel", keywords: "ioc indicator threatfox watchlist opencti" },
    { label: "World Monitor", to: "/world-monitor", icon: Globe, testid: "nav-world-monitor", keywords: "world monitor global events situational awareness ransomware kev news geopolitical board" },
    { label: "Geo-Forecast (Experimental)", to: "/geo-forecast", icon: Flask, testid: "nav-geo-forecast", keywords: "pythia forecast experimental geo" },
  ] },
  { key: "assets", label: "Assets", icon: HardDrives, items: [
    { label: "Assets", to: "/assets", icon: HardDrives, testid: "nav-assets", keywords: "hosts devices machines inventory endpoints" },
    { label: "Products", to: "/products", icon: Stack, testid: "nav-products", keywords: "software applications products services" },
    { label: "Application Inventory", to: "/app-inventory", icon: Cube, testid: "nav-app-inventory", keywords: "saas shadow it applications software inventory oauth" },
    { label: "Directory", to: "/directory", icon: UsersThree, testid: "nav-directory", keywords: "users groups entra edr defender intune identity" },
    { label: "End-of-Life Software", to: "/admin/eol-tracking", icon: CalendarX, testid: "nav-eol-tracking", keywords: "eol eos obsolete unsupported end of life" },
    { label: "SBOM / Dependencies", to: "/admin/sbom", icon: Package, testid: "nav-sbom", keywords: "sbom dependencies cyclonedx spdx components" },
    { label: "Criticality Scoring", to: "/admin/criticality-scoring", icon: Stack, testid: "nav-criticality-scoring", keywords: "criticality asset importance scoring" },
  ] },
  { key: "scanning", label: "Scanning", icon: MagnifyingGlass, items: [
    { label: "Engagements", to: "/engagements", icon: Lightning, testid: "nav-engagements", keywords: "scans runs imports scan history" },
    { label: "Import Jobs", to: "/imports", icon: Database, testid: "nav-imports", keywords: "import upload csv xlsx jobs" },
    { label: "Scan Schedule", to: "/admin/scan-schedule", icon: CalendarBlank, testid: "nav-scan-schedule", keywords: "schedule cron scan timing" },
    { label: "Web Scan Uploads", to: "/admin/web-scans", icon: Database, testid: "nav-web-scans", keywords: "web scan upload" },
    { label: "Nmap Scan Uploads", to: "/admin/nmap-scans", icon: Database, testid: "nav-nmap-scans", keywords: "nmap port scan network" },
    { label: "Web App Scans (Nikto)", to: "/admin/nikto-scans", icon: Globe, testid: "nav-nikto-scans", keywords: "nikto web app scanner" },
    { label: "Container Image Scanning", to: "/admin/container-scan", icon: Cube, testid: "nav-container-scan", keywords: "docker trivy image container sbom" },
    { label: "Secrets Scanning", to: "/admin/secrets-scan", icon: Key, testid: "nav-secrets-scan", keywords: "secrets credentials leak git repo detect-secrets" },
    { label: "YARA Scanning", to: "/admin/yara", icon: Virus, testid: "nav-yara", keywords: "yara malware rules" },
  ] },
  { key: "integrations", label: "Integrations", icon: PlugsConnected, items: [
    { label: "Connectors", to: "/integrations", icon: PlugsConnected, testid: "nav-integrations", keywords: "integrations connectors api qualys nessus defender" },
    { label: "Splunk", to: "/admin/splunk", icon: Database, testid: "nav-splunk", keywords: "splunk saved search siem" },
    { label: "Wazuh", to: "/admin/wazuh", icon: ShieldCheck, testid: "nav-wazuh", keywords: "wazuh indexer siem edr" },
    { label: "Ticketing / SOAR", to: "/admin/ticketing", icon: WebhooksLogo, testid: "nav-ticketing", keywords: "jira servicenow soar webhook ticketing" },
    { label: "ChatOps", to: "/admin/chatops", icon: SlackLogo, testid: "nav-chatops", keywords: "slack teams chatops chat" },
  ] },
  { key: "risk", label: "Risk & Reviews", icon: Warning, items: [
    { label: "Risk Register", to: "/risk-register", icon: Warning, testid: "nav-risk-register", keywords: "risk register enterprise risk" },
    { label: "Security Reviews", to: "/security-reviews", icon: ClipboardText, testid: "nav-security-reviews", keywords: "vendor review assessment questionnaire security review" },
    { label: "Vendor & Third-Party Risk", to: "/vendors", icon: Buildings, testid: "nav-vendors", keywords: "vendor third party supplier tprm" },
    { label: "Threat Modeling", to: "/threat-modeling", icon: FlowArrow, testid: "nav-threat-modeling", keywords: "stride threat model dfd" },
  ] },
  { key: "reports", label: "Reports & Compliance", icon: FileArrowDown, items: [
    { label: "Reports", to: "/reports", icon: FileArrowDown, testid: "nav-reports", keywords: "report export pdf docx executive" },
    { label: "Compliance", to: "/compliance", icon: ClipboardText, testid: "nav-compliance", keywords: "soc2 iso27001 pci nist cis framework compliance" },
    { label: "OWASP WSTG Library", to: "/wstg", icon: ShieldCheck, testid: "nav-wstg", keywords: "owasp wstg web security testing guide methodology test cases pentest" },
  ] },
  { key: "admin", label: "Administration", icon: GearSix, items: [
    { label: "Admin", to: "/admin", icon: GearSix, testid: "nav-admin", keywords: "administration settings" },
    { label: "Settings", to: "/admin/settings", icon: GearSix, testid: "nav-settings", keywords: "settings preferences feature flags configuration" },
    { label: "Users", to: "/admin/users", icon: UsersThree, testid: "nav-users", keywords: "users accounts people access" },
    { label: "Teams", to: "/admin/teams", icon: UsersThree, testid: "nav-teams", keywords: "teams groups org" },
    { label: "Role Access", to: "/admin/rbac", icon: LockKey, testid: "nav-rbac", keywords: "rbac role access permissions" },
    { label: "Notifications", to: "/admin/notifications", icon: Bell, testid: "nav-notifications", keywords: "notifications email alerts digest" },
    { label: "System Health", to: "/admin/health", icon: Heartbeat, testid: "nav-health", keywords: "health status loops connectors observability uptime" },
    { label: "Backups", to: "/admin/backups", icon: HardDrive, testid: "nav-backups", keywords: "backup restore export database" },
    { label: "Data Retention", to: "/admin/retention", icon: Archive, testid: "nav-retention", keywords: "retention purge data lifecycle" },
    { label: "Audit Log", to: "/admin/audit-log", icon: Notepad, testid: "nav-audit-log", keywords: "audit log activity history" },
    { label: "Assignment Rules", to: "/admin/assignment-rules", icon: GearSix, testid: "nav-rules", keywords: "assignment ownership routing rules" },
    { label: "Ownership Map", to: "/admin/ownership", icon: GearSix, testid: "nav-ownership", keywords: "ownership team mapping" },
    { label: "SLA Policies", to: "/admin/sla-policies", icon: ShieldCheck, testid: "nav-sla", keywords: "sla policy due date deadline" },
    { label: "Approval Routing", to: "/admin/approval-routing", icon: FlowArrow, testid: "nav-approval-routing", keywords: "approval routing workflow authorization" },
  ] },
];

// Flat view for the palette (and anything else that wants "every page").
export const NAV = SECTIONS.flatMap((s) => s.items.map((i) => ({ ...i, group: s.label, section: s.key })));

// Which section owns a path: exact match first, then the longest matching
// prefix (so /findings/123 belongs to Findings, /admin/users to Administration).
export function sectionForPath(path) {
  let best = null, bestLen = -1;
  for (const s of SECTIONS) {
    for (const i of s.items) {
      if (i.to === path) return s.key;
      if (i.to !== "/" && path.startsWith(i.to + "/") && i.to.length > bestLen) { best = s.key; bestLen = i.to.length; }
    }
  }
  return best;
}

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
