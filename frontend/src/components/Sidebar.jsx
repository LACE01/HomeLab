import { useState, useRef, useEffect, Children, isValidElement } from "react";
import { NavLink, useNavigate, Link } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import {
  ChartLineUp, ListChecks, HardDrives, Stack, Lightning, Ticket,
  ShieldCheck, PlugsConnected, FileArrowDown, GearSix, SignOut, Database,
  UsersThree, Bell, ShareNetwork, BookOpen, Robot, Globe, Certificate, Package, MagnifyingGlass, ClipboardText, SlackLogo, Heartbeat, HardDrive, Notepad, Virus, FlowArrow,
  CaretDown, LockKey, CalendarBlank, FirstAidKit, Siren, SlidersHorizontal, Devices, Binoculars, Gauge, WebhooksLogo, Archive, Broadcast, Warning,
  Buildings, At, CalendarX, Cube, Key,
} from "@phosphor-icons/react";

const COLLAPSE_KEY = "vulnops.sidebar.collapsedGroups";
const loadCollapsed = () => {
  try { return JSON.parse(localStorage.getItem(COLLAPSE_KEY) || "{}"); } catch { return {}; }
};

const NavItem = ({ to, icon: Icon, label, testid }) => {
  const { canAccess } = useAuth();
  // Module key == route path (see backend/rbac.py) -- hide nav items a role's Role
  // Access config doesn't grant, so the sidebar reflects what the backend will
  // actually let this user do rather than just letting them click into a 403.
  if (!canAccess(to)) return null;
  return (
    <NavLink
      to={to}
      end={to === "/"}
      data-testid={testid}
      className={({ isActive }) =>
        `flex items-center gap-2.5 px-3 py-1.5 rounded-md text-[13px] transition-colors duration-150 ${
          isActive
            ? "bg-blue-500/10 text-blue-300 border-l-2 border-blue-400"
            : "text-slate-400 hover:bg-slate-800/40 hover:text-slate-100"
        }`
      }
    >
      <Icon size={16} weight="duotone" />
      {label}
    </NavLink>
  );
};

const Group = ({ title, children, collapsed, onToggle }) => {
  // NavItem hides itself (returns null) for modules the user's role can't access --
  // if every item in a group got hidden that way, don't show an empty collapsible
  // section with nothing under it.
  const visibleCount = Children.toArray(children).filter(isValidElement).length;
  if (visibleCount === 0) return null;
  return (
    <div className="mb-4">
      <button onClick={onToggle}
        className="w-full flex items-center justify-between px-3 mb-1.5 text-[10px] uppercase tracking-wider text-slate-600 hover:text-slate-400 font-mono">
        <span>{title}</span>
        <CaretDown size={10} className={`transition-transform ${collapsed ? "-rotate-90" : ""}`}/>
      </button>
      {!collapsed && <div className="flex flex-col gap-0.5">{children}</div>}
    </div>
  );
};

// Every page renders its own <Layout> -> <Sidebar>, so React Router unmounts and
// remounts a brand-new Sidebar instance on every navigation (there's no single
// persistent shell wrapping all routes) -- a plain React ref/state scroll position
// can't survive that remount on its own, which is why clicking a nav item used to
// snap the list back to the top even when you were scrolled deep into e.g.
// Administration. SCROLL_KEY persists the last scroll offset in sessionStorage
// (survives remounts within the tab, cleared when the tab closes -- this is
// transient UI state, not a durable preference like the collapsed-groups setting
// below, which intentionally uses localStorage instead) and restores it the instant
// the new Sidebar mounts.
const SCROLL_KEY = "vulnops_sidebar_scroll";

export default function Sidebar() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  const [collapsed, setCollapsed] = useState(loadCollapsed());
  const navRef = useRef(null);
  const toggleGroup = (key) => setCollapsed(prev => {
    const next = { ...prev, [key]: !prev[key] };
    localStorage.setItem(COLLAPSE_KEY, JSON.stringify(next));
    return next;
  });

  useEffect(() => {
    const saved = sessionStorage.getItem(SCROLL_KEY);
    if (saved && navRef.current) navRef.current.scrollTop = parseInt(saved, 10) || 0;
  }, []);

  return (
    <aside data-testid="sidebar" className="w-60 shrink-0 bg-[#0D1117] border-r border-[#30363D] flex flex-col h-screen sticky top-0">
      <div className="px-4 py-4 border-b border-[#30363D] flex items-center gap-2">
        <Binoculars size={22} weight="duotone" className="text-blue-400" />
        <div>
          <div className="text-[15px] font-semibold tracking-tight text-slate-100">Nightwatch</div>
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Security Operations</div>
        </div>
      </div>

      <nav ref={navRef} onScroll={(e) => sessionStorage.setItem(SCROLL_KEY, String(e.currentTarget.scrollTop))} className="flex-1 overflow-y-auto py-3 px-2">
        <Group title="Overview" collapsed={!!collapsed["Overview"]} onToggle={()=>toggleGroup("Overview")}>
          <NavItem to="/" icon={ChartLineUp} label="Dashboard" testid="nav-dashboard" />
          <NavItem to="/soc" icon={Gauge} label="SOC Overview" testid="nav-soc" />
          <NavItem to="/operational" icon={Lightning} label="Team Dashboards" testid="nav-operational" />
        </Group>
        <Group title="Vulnerability Management" collapsed={!!collapsed["Vulnerability Management"]} onToggle={()=>toggleGroup("Vulnerability Management")}>
          <NavItem to="/findings" icon={ListChecks} label="Findings" testid="nav-findings" />
          <NavItem to="/attack-paths" icon={ShareNetwork} label="Attack Paths" testid="nav-attack-paths" />
          <NavItem to="/exposure" icon={Globe} label="Exposure" testid="nav-exposure" />
          <NavItem to="/admin/tls-certs" icon={Certificate} label="TLS Certificates" testid="nav-tls-certs" />
          <NavItem to="/admin/email-auth" icon={At} label="Email Authentication" testid="nav-email-auth" />
          <NavItem to="/admin/eol-tracking" icon={CalendarX} label="End-of-Life Software" testid="nav-eol-tracking" />
          <NavItem to="/admin/container-scan" icon={Cube} label="Container Image Scanning" testid="nav-container-scan" />
          <NavItem to="/admin/secrets-scan" icon={Key} label="Secrets Scanning" testid="nav-secrets-scan" />
          <NavItem to="/easm" icon={MagnifyingGlass} label="Attack Surface" testid="nav-easm" />
          <NavItem to="/tickets" icon={Ticket} label="Tickets" testid="nav-tickets" />
          <NavItem to="/exceptions" icon={ShieldCheck} label="Exceptions" testid="nav-exceptions" />
          <NavItem to="/admin/playbooks" icon={BookOpen} label="Playbooks" testid="nav-playbooks" />
          <NavItem to="/automation" icon={Robot} label="Automation" testid="nav-automation" />
        </Group>
        <Group title="Detection & Response" collapsed={!!collapsed["Detection & Response"]} onToggle={()=>toggleGroup("Detection & Response")}>
          <NavItem to="/alerts" icon={Siren} label="Security Alerts" testid="nav-alerts" />
          <NavItem to="/admin/threat-intel" icon={Binoculars} label="Threat Intel Watchlist" testid="nav-threat-intel" />
          <NavItem to="/admin/albert" icon={Broadcast} label="Albert Network Monitoring" testid="nav-albert" />
          <NavItem to="/ir/wizard" icon={FirstAidKit} label="Triage Wizard" testid="nav-ir-wizard" />
          <NavItem to="/ir/cases" icon={Siren} label="IR Cases" testid="nav-ir-cases" />
          <NavItem to="/admin/ir-setup" icon={SlidersHorizontal} label="IR Setup" testid="nav-ir-setup" />
        </Group>
        <Group title="Asset Inventory" collapsed={!!collapsed["Asset Inventory"]} onToggle={()=>toggleGroup("Asset Inventory")}>
          <NavItem to="/assets" icon={HardDrives} label="Assets" testid="nav-assets" />
          <NavItem to="/products" icon={Stack} label="Products" testid="nav-products" />
          <NavItem to="/engagements" icon={Lightning} label="Engagements" testid="nav-engagements" />
          <NavItem to="/directory" icon={UsersThree} label="Directory" testid="nav-directory" />
        </Group>
        <Group title="Scanning & Integrations" collapsed={!!collapsed["Scanning & Integrations"]} onToggle={()=>toggleGroup("Scanning & Integrations")}>
          <NavItem to="/integrations" icon={PlugsConnected} label="Connectors" testid="nav-integrations" />
          <NavItem to="/imports" icon={Database} label="Import Jobs" testid="nav-imports" />
          <NavItem to="/admin/web-scans" icon={Database} label="Web Scan Uploads" testid="nav-web-scans" />
          <NavItem to="/admin/nmap-scans" icon={Database} label="Nmap Scan Uploads" testid="nav-nmap-scans" />
          <NavItem to="/admin/nikto-scans" icon={Globe} label="Web App Scans (Nikto)" testid="nav-nikto-scans" />
          <NavItem to="/admin/recon-osint" icon={MagnifyingGlass} label="Recon & OSINT" testid="nav-recon-osint" />
          <NavItem to="/admin/criticality-scoring" icon={Stack} label="Criticality Scoring" testid="nav-criticality-scoring" />
          <NavItem to="/admin/sbom" icon={Package} label="SBOM / Dependencies" testid="nav-sbom" />
          <NavItem to="/admin/yara" icon={Virus} label="YARA Scanning" testid="nav-yara" />
          <NavItem to="/admin/scan-schedule" icon={CalendarBlank} label="Scan Schedule" testid="nav-scan-schedule" />
          <NavItem to="/admin/splunk" icon={Database} label="Splunk" testid="nav-splunk" />
          <NavItem to="/admin/wazuh" icon={ShieldCheck} label="Wazuh" testid="nav-wazuh" />
          <NavItem to="/admin/ticketing" icon={WebhooksLogo} label="Ticketing / SOAR" testid="nav-ticketing" />
        </Group>
        <Group title="Reports & Compliance" collapsed={!!collapsed["Reports & Compliance"]} onToggle={()=>toggleGroup("Reports & Compliance")}>
          <NavItem to="/reports" icon={FileArrowDown} label="Reports" testid="nav-reports" />
          <NavItem to="/compliance" icon={ClipboardText} label="Compliance" testid="nav-compliance" />
          <NavItem to="/risk-register" icon={Warning} label="Risk Register" testid="nav-risk-register" />
          <NavItem to="/vendors" icon={Buildings} label="Vendor & Third-Party Risk" testid="nav-vendors" />
        </Group>
        <Group title="Administration" collapsed={!!collapsed["Administration"]} onToggle={()=>toggleGroup("Administration")}>
          <NavItem to="/admin" icon={GearSix} label="Admin" testid="nav-admin" />
          <NavItem to="/admin/settings" icon={GearSix} label="Settings" testid="nav-settings" />
          <NavItem to="/admin/users" icon={UsersThree} label="Users" testid="nav-users" />
          <NavItem to="/admin/teams" icon={UsersThree} label="Teams" testid="nav-teams" />
          <NavItem to="/admin/notifications" icon={Bell} label="Notifications" testid="nav-notifications" />
          <NavItem to="/admin/chatops" icon={SlackLogo} label="ChatOps" testid="nav-chatops" />
          <NavItem to="/admin/health" icon={Heartbeat} label="System Health" testid="nav-health" />
          <NavItem to="/admin/backups" icon={HardDrive} label="Backups" testid="nav-backups" />
          <NavItem to="/admin/retention" icon={Archive} label="Data Retention" testid="nav-retention" />
          <NavItem to="/admin/audit-log" icon={Notepad} label="Audit Log" testid="nav-audit-log" />
          <NavItem to="/admin/assignment-rules" icon={GearSix} label="Assignment Rules" testid="nav-rules" />
          <NavItem to="/admin/ownership" icon={GearSix} label="Ownership Map" testid="nav-ownership" />
          <NavItem to="/admin/sla-policies" icon={ShieldCheck} label="SLA Policies" testid="nav-sla" />
          <NavItem to="/admin/approval-routing" icon={FlowArrow} label="Approval Routing" testid="nav-approval-routing" />
          <NavItem to="/admin/rbac" icon={LockKey} label="Role Access" testid="nav-rbac" />
        </Group>
      </nav>

      <div className="border-t border-[#30363D] p-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-[12px] text-slate-200 truncate">{user?.name}</div>
            <div className="text-[10px] text-slate-500 font-mono uppercase">{user?.role}</div>
          </div>
          <Link to="/security" title="Security settings" className="text-slate-500 hover:text-slate-200 transition-colors">
            <Devices size={18} />
          </Link>
          <button
            data-testid="logout-btn"
            onClick={async () => { await logout(); nav("/login"); }}
            className="text-slate-500 hover:text-slate-200 transition-colors"
            title="Sign out"
          >
            <SignOut size={18} />
          </button>
        </div>
      </div>
    </aside>
  );
}
