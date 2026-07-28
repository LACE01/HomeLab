import { useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import "@/index.css";

import Login from "@/pages/Login";
import AuthCallback from "@/pages/AuthCallback";
import Dashboard from "@/pages/Dashboard";
import Findings from "@/pages/Findings";
import FindingDetail from "@/pages/FindingDetail";
import { Assets, AssetDetail } from "@/pages/Assets";
import { Products, Engagements, Tickets, Exceptions } from "@/pages/Operations";
import RequestRiskAcceptance from "@/pages/RequestRiskAcceptance";
import ExceptionDetail from "@/pages/ExceptionDetail";
import ApprovalRouting from "@/pages/ApprovalRouting";
import ProductDetail from "@/pages/ProductDetail";
import { Integrations, ImportJobs, Admin } from "@/pages/AdminAndIntegrations";
import Reports from "@/pages/Reports";
import Operational from "@/pages/Operational";
import { AssignmentRules, OwnershipMappings } from "@/pages/Ownership";
import Users from "@/pages/Users";
import Notifications from "@/pages/Notifications";
import AttackPaths from "@/pages/AttackPaths";
import SlaPolicies from "@/pages/SlaPolicies";
import WebScansUpload from "@/pages/WebScansUpload";
import Teams from "@/pages/Teams";
import Playbooks from "@/pages/Playbooks";
import PlaybookDetail from "@/pages/PlaybookDetail";
import Automation from "@/pages/Automation";
import Exposure from "@/pages/Exposure";
import NmapUpload from "@/pages/NmapUpload";
import NiktoScans from "@/pages/NiktoScans";
import ReconOSINT from "@/pages/ReconOSINT";
import CriticalityScoring from "@/pages/CriticalityScoring";
import TlsCerts from "@/pages/TlsCerts";
import EmailAuthMonitoring from "@/pages/EmailAuthMonitoring";
import EolTracking from "@/pages/EolTracking";
import ContainerScanning from "@/pages/ContainerScanning";
import SecretsScanning from "@/pages/SecretsScanning";
import SbomUpload from "@/pages/SbomUpload";
import Easm from "@/pages/Easm";
import Compliance from "@/pages/Compliance";
import ChatOps from "@/pages/ChatOps";
import OpsHealth from "@/pages/OpsHealth";
import Backups from "@/pages/Backups";
import DataRetention from "@/pages/DataRetention";
import AuditLog from "@/pages/AuditLog";
import Yara from "@/pages/Yara";
import RoleAccess from "@/pages/RoleAccess";
import ScanSchedule from "@/pages/ScanSchedule";
import IRWizard from "@/pages/IRWizard";
import { IRCases, IRCaseDetail } from "@/pages/IRCases";
import IRAdminSetup from "@/pages/IRAdminSetup";
import ChangePassword from "@/pages/ChangePassword";
import Security from "@/pages/Security";
import SecurityAlerts from "@/pages/SecurityAlerts";
import SplunkIntegration from "@/pages/SplunkIntegration";
import WazuhIntegration from "@/pages/WazuhIntegration";
import SocOverview from "@/pages/SocOverview";
import TicketingSoar from "@/pages/TicketingSoar";
import ThreatIntelWatchlist from "@/pages/ThreatIntelWatchlist";
import AlbertMonitoring from "@/pages/AlbertMonitoring";
import RiskRegister from "@/pages/RiskRegister";
import SecurityReviews from "@/pages/SecurityReviews";
import SecurityReviewDetail from "@/pages/SecurityReviewDetail";
import RiskDetail from "@/pages/RiskDetail";
import VendorManagement from "@/pages/VendorManagement";
import VendorDetail from "@/pages/VendorDetail";
import Directory from "@/pages/Directory";
import Settings from "@/pages/Settings";

const Protected = ({ children, module }) => {
  const { user, loading, canAccess } = useAuth();
  const location = useLocation();
  if (loading) return <div className="min-h-screen flex items-center justify-center bg-[#090C10] text-slate-500">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  // A temp password (set by an admin at account creation) forces this before
  // anything else in the app is reachable -- no route, including deep links typed
  // directly into the address bar, bypasses it.
  if (user.must_change_password && location.pathname !== "/change-password") {
    return <Navigate to="/change-password" replace />;
  }
  // Direct/typed URL to a module this role doesn't have -- the Sidebar already hides
  // the nav link, but the route itself needs its own guard too (nothing stops someone
  // from just typing the URL). The backend enforces this for real on its main data
  // endpoint for this module; this is the matching front-end message, not the security
  // boundary itself.
  if (module && !canAccess(module)) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#090C10]">
        <div className="text-center max-w-sm">
          <div className="text-slate-300 text-[15px] font-medium mb-1.5">Access restricted</div>
          <div className="text-slate-500 text-[13px] leading-relaxed">
            Your role ({user.role}) doesn't have access to this module. Ask an admin to grant it under
            Administration → Role Access.
          </div>
        </div>
      </div>
    );
  }
  return children;
};

const AppRouter = () => {
  const location = useLocation();
  // Explicit, instant scroll-to-top on every route change. Without this, switching
  // between modules whose page heights differ leaves the browser's default scroll
  // position wherever it happens to clamp to on the new (often shorter) page --
  // which reads as "it randomly jumps around" rather than a clean, deliberate reset.
  useEffect(() => {
    window.scrollTo(0, 0);
  }, [location.pathname]);
  // CRITICAL: Detect OAuth callback synchronously during render — before any Protected gating
  if (location.hash?.includes("session_id=")) return <AuthCallback />;
  return (
    <Routes>
      <Route path="/login" element={<Login/>}/>
      <Route path="/auth/callback" element={<AuthCallback/>}/>
      <Route path="/change-password" element={<Protected><ChangePassword/></Protected>}/>
      <Route path="/security" element={<Protected><Security/></Protected>}/>
      <Route path="/alerts" element={<Protected><SecurityAlerts/></Protected>}/>
      <Route path="/admin/splunk" element={<Protected><SplunkIntegration/></Protected>}/>
      <Route path="/admin/wazuh" element={<Protected><WazuhIntegration/></Protected>}/>
      <Route path="/soc" element={<Protected><SocOverview/></Protected>}/>
      <Route path="/admin/ticketing" element={<Protected><TicketingSoar/></Protected>}/>
      <Route path="/admin/threat-intel" element={<Protected><ThreatIntelWatchlist/></Protected>}/>
      <Route path="/admin/albert" element={<Protected module="/admin/albert"><AlbertMonitoring/></Protected>}/>
      <Route path="/" element={<Protected module="/"><Dashboard/></Protected>}/>
      <Route path="/findings" element={<Protected module="/findings"><Findings/></Protected>}/>
      <Route path="/findings/:id" element={<Protected module="/findings"><FindingDetail/></Protected>}/>
      <Route path="/assets" element={<Protected module="/assets"><Assets/></Protected>}/>
      <Route path="/assets/:id" element={<Protected module="/assets"><AssetDetail/></Protected>}/>
      <Route path="/products" element={<Protected module="/products"><Products/></Protected>}/>
      <Route path="/products/:id" element={<Protected module="/products"><ProductDetail/></Protected>}/>
      <Route path="/engagements" element={<Protected module="/engagements"><Engagements/></Protected>}/>
      <Route path="/tickets" element={<Protected module="/tickets"><Tickets/></Protected>}/>
      <Route path="/exceptions" element={<Protected module="/exceptions"><Exceptions/></Protected>}/>
      <Route path="/exceptions/new" element={<Protected module="/exceptions"><RequestRiskAcceptance/></Protected>}/>
      <Route path="/exceptions/:id" element={<Protected module="/exceptions"><ExceptionDetail/></Protected>}/>
      <Route path="/admin/approval-routing" element={<Protected module="/admin/approval-routing"><ApprovalRouting/></Protected>}/>
      <Route path="/integrations" element={<Protected module="/integrations"><Integrations/></Protected>}/>
      <Route path="/imports" element={<Protected module="/imports"><ImportJobs/></Protected>}/>
      <Route path="/reports" element={<Protected module="/reports"><Reports/></Protected>}/>
      <Route path="/admin" element={<Protected module="/admin"><Admin/></Protected>}/>
      <Route path="/operational" element={<Protected module="/operational"><Operational/></Protected>}/>
      <Route path="/attack-paths" element={<Protected module="/attack-paths"><AttackPaths/></Protected>}/>
      <Route path="/admin/tls-certs" element={<Protected module="/admin/tls-certs"><TlsCerts/></Protected>}/>
      <Route path="/admin/email-auth" element={<Protected module="/admin/email-auth"><EmailAuthMonitoring/></Protected>}/>
      <Route path="/admin/eol-tracking" element={<Protected module="/admin/eol-tracking"><EolTracking/></Protected>}/>
      <Route path="/admin/container-scan" element={<Protected module="/admin/container-scan"><ContainerScanning/></Protected>}/>
      <Route path="/admin/secrets-scan" element={<Protected module="/admin/secrets-scan"><SecretsScanning/></Protected>}/>
      <Route path="/admin/sbom" element={<Protected module="/admin/sbom"><SbomUpload/></Protected>}/>
      <Route path="/admin/yara" element={<Protected module="/admin/yara"><Yara/></Protected>}/>
      <Route path="/easm" element={<Protected module="/easm"><Easm/></Protected>}/>
      <Route path="/compliance" element={<Protected module="/compliance"><Compliance/></Protected>}/>
      <Route path="/risk-register" element={<Protected module="/risk-register"><RiskRegister/></Protected>}/>
      <Route path="/risk-register/:id" element={<Protected module="/risk-register"><RiskDetail/></Protected>}/>
      <Route path="/security-reviews" element={<Protected module="/security-reviews"><SecurityReviews/></Protected>}/>
      <Route path="/security-reviews/:id" element={<Protected module="/security-reviews"><SecurityReviewDetail/></Protected>}/>
      <Route path="/vendors" element={<Protected module="/vendors"><VendorManagement/></Protected>}/>
      <Route path="/vendors/:id" element={<Protected module="/vendors"><VendorDetail/></Protected>}/>
      <Route path="/directory" element={<Protected module="/directory"><Directory/></Protected>}/>
      <Route path="/admin/settings" element={<Protected module="/admin"><Settings/></Protected>}/>
      <Route path="/admin/chatops" element={<Protected module="/admin/chatops"><ChatOps/></Protected>}/>
      <Route path="/admin/health" element={<Protected module="/admin/health"><OpsHealth/></Protected>}/>
      <Route path="/admin/backups" element={<Protected module="/admin/backups"><Backups/></Protected>}/>
      <Route path="/admin/retention" element={<Protected module="/admin/retention"><DataRetention/></Protected>}/>
      <Route path="/admin/audit-log" element={<Protected module="/admin/audit-log"><AuditLog/></Protected>}/>
      <Route path="/admin/assignment-rules" element={<Protected module="/admin/assignment-rules"><AssignmentRules/></Protected>}/>
      <Route path="/admin/ownership" element={<Protected module="/admin/ownership"><OwnershipMappings/></Protected>}/>
      <Route path="/admin/sla-policies" element={<Protected module="/admin/sla-policies"><SlaPolicies/></Protected>}/>
      <Route path="/admin/playbooks" element={<Protected module="/admin/playbooks"><Playbooks/></Protected>}/>
      <Route path="/admin/playbooks/:id" element={<Protected module="/admin/playbooks"><PlaybookDetail/></Protected>}/>
      <Route path="/automation" element={<Protected module="/automation"><Automation/></Protected>}/>
      <Route path="/exposure" element={<Protected module="/exposure"><Exposure/></Protected>}/>
      <Route path="/admin/nmap-scans" element={<Protected module="/admin/nmap-scans"><NmapUpload/></Protected>}/>
      <Route path="/admin/nikto-scans" element={<Protected module="/admin/nikto-scans"><NiktoScans/></Protected>}/>
      <Route path="/admin/recon-osint" element={<Protected module="/admin/recon-osint"><ReconOSINT/></Protected>}/>
      <Route path="/admin/criticality-scoring" element={<Protected module="/admin/criticality-scoring"><CriticalityScoring/></Protected>}/>
      <Route path="/admin/web-scans" element={<Protected module="/admin/web-scans"><WebScansUpload/></Protected>}/>
      <Route path="/admin/users" element={<Protected module="/admin/users"><Users/></Protected>}/>
      <Route path="/admin/teams" element={<Protected module="/admin/teams"><Teams/></Protected>}/>
      <Route path="/admin/notifications" element={<Protected module="/admin/notifications"><Notifications/></Protected>}/>
      <Route path="/admin/rbac" element={<Protected module="/admin/rbac"><RoleAccess/></Protected>}/>
      <Route path="/admin/scan-schedule" element={<Protected module="/admin/scan-schedule"><ScanSchedule/></Protected>}/>
      <Route path="/ir/wizard" element={<Protected module="/ir/wizard"><IRWizard/></Protected>}/>
      <Route path="/ir/cases" element={<Protected module="/ir/cases"><IRCases/></Protected>}/>
      <Route path="/ir/cases/:id" element={<Protected module="/ir/cases"><IRCaseDetail/></Protected>}/>
      <Route path="/admin/ir-setup" element={<Protected module="/admin/ir-setup"><IRAdminSetup/></Protected>}/>
    </Routes>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <TooltipProvider delayDuration={200}>
        <BrowserRouter>
          <AppRouter/>
        </BrowserRouter>
        <Toaster richColors position="top-right" />
      </TooltipProvider>
    </AuthProvider>
  );
}
