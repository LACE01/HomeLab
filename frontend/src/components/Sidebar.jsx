import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "@/lib/auth";
import {
  ChartLineUp, ListChecks, HardDrives, Stack, Lightning, Ticket,
  ShieldCheck, PlugsConnected, FileArrowDown, GearSix, SignOut, Database, Bug,
  UsersThree, Bell, ShareNetwork, BookOpen, Robot, Globe, Certificate, Package, MagnifyingGlass, ClipboardText, SlackLogo,
} from "@phosphor-icons/react";

const NavItem = ({ to, icon: Icon, label, testid }) => (
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

const Group = ({ title, children }) => (
  <div className="mb-4">
    <div className="px-3 mb-1.5 text-[10px] uppercase tracking-wider text-slate-600 font-mono">{title}</div>
    <div className="flex flex-col gap-0.5">{children}</div>
  </div>
);

export default function Sidebar() {
  const { user, logout } = useAuth();
  const nav = useNavigate();
  return (
    <aside data-testid="sidebar" className="w-60 shrink-0 bg-[#0D1117] border-r border-[#30363D] flex flex-col h-screen sticky top-0">
      <div className="px-4 py-4 border-b border-[#30363D] flex items-center gap-2">
        <Bug size={22} weight="duotone" className="text-blue-400" />
        <div>
          <div className="text-[15px] font-semibold tracking-tight text-slate-100">VulnOps</div>
          <div className="text-[10px] font-mono text-slate-500 uppercase tracking-wider">Vulnerability Operations</div>
        </div>
      </div>

      <nav className="flex-1 overflow-y-auto py-3 px-2">
        <Group title="Operations">
          <NavItem to="/" icon={ChartLineUp} label="Dashboard" testid="nav-dashboard" />
          <NavItem to="/operational" icon={Lightning} label="Operational" testid="nav-operational" />
          <NavItem to="/findings" icon={ListChecks} label="Findings" testid="nav-findings" />
          <NavItem to="/attack-paths" icon={ShareNetwork} label="Attack Paths" testid="nav-attack-paths" />
          <NavItem to="/exposure" icon={Globe} label="Exposure" testid="nav-exposure" />
          <NavItem to="/admin/tls-certs" icon={Certificate} label="TLS Certificates" testid="nav-tls-certs" />
          <NavItem to="/easm" icon={MagnifyingGlass} label="Attack Surface" testid="nav-easm" />
          <NavItem to="/tickets" icon={Ticket} label="Tickets" testid="nav-tickets" />
          <NavItem to="/exceptions" icon={ShieldCheck} label="Exceptions" testid="nav-exceptions" />
          <NavItem to="/admin/playbooks" icon={BookOpen} label="Playbooks" testid="nav-playbooks" />
          <NavItem to="/automation" icon={Robot} label="Automation" testid="nav-automation" />
        </Group>
        <Group title="Inventory">
          <NavItem to="/assets" icon={HardDrives} label="Assets" testid="nav-assets" />
          <NavItem to="/products" icon={Stack} label="Products" testid="nav-products" />
          <NavItem to="/engagements" icon={Lightning} label="Engagements" testid="nav-engagements" />
        </Group>
        <Group title="Integrations">
          <NavItem to="/integrations" icon={PlugsConnected} label="Connectors" testid="nav-integrations" />
          <NavItem to="/imports" icon={Database} label="Import Jobs" testid="nav-imports" />
          <NavItem to="/admin/web-scans" icon={Database} label="Web Scan Uploads" testid="nav-web-scans" />
          <NavItem to="/admin/nmap-scans" icon={Database} label="Nmap Scan Uploads" testid="nav-nmap-scans" />
          <NavItem to="/admin/sbom" icon={Package} label="SBOM / Dependencies" testid="nav-sbom" />
        </Group>
        <Group title="Reports & Admin">
          <NavItem to="/reports" icon={FileArrowDown} label="Reports" testid="nav-reports" />
          <NavItem to="/compliance" icon={ClipboardText} label="Compliance" testid="nav-compliance" />
          <NavItem to="/admin" icon={GearSix} label="Admin" testid="nav-admin" />
          <NavItem to="/admin/users" icon={UsersThree} label="Users" testid="nav-users" />
          <NavItem to="/admin/teams" icon={UsersThree} label="Teams" testid="nav-teams" />
          <NavItem to="/admin/notifications" icon={Bell} label="Notifications" testid="nav-notifications" />
          <NavItem to="/admin/chatops" icon={SlackLogo} label="ChatOps" testid="nav-chatops" />
          <NavItem to="/admin/assignment-rules" icon={GearSix} label="Assignment Rules" testid="nav-rules" />
          <NavItem to="/admin/ownership" icon={GearSix} label="Ownership Map" testid="nav-ownership" />
          <NavItem to="/admin/sla-policies" icon={ShieldCheck} label="SLA Policies" testid="nav-sla" />
        </Group>
      </nav>

      <div className="border-t border-[#30363D] p-3">
        <div className="flex items-center justify-between gap-2">
          <div className="min-w-0">
            <div className="text-[12px] text-slate-200 truncate">{user?.name}</div>
            <div className="text-[10px] text-slate-500 font-mono uppercase">{user?.role}</div>
          </div>
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
