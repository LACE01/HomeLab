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
import SbomUpload from "@/pages/SbomUpload";
import Easm from "@/pages/Easm";
import Compliance from "@/pages/Compliance";
import ChatOps from "@/pages/ChatOps";
import OpsHealth from "@/pages/OpsHealth";
import Backups from "@/pages/Backups";
import AuditLog from "@/pages/AuditLog";
import Yara from "@/pages/Yara";

const Protected = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen flex items-center justify-center bg-[#090C10] text-slate-500">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
};

const AppRouter = () => {
  const location = useLocation();
  // CRITICAL: Detect OAuth callback synchronously during render — before any Protected gating
  if (location.hash?.includes("session_id=")) return <AuthCallback />;
  return (
    <Routes>
      <Route path="/login" element={<Login/>}/>
      <Route path="/auth/callback" element={<AuthCallback/>}/>
      <Route path="/" element={<Protected><Dashboard/></Protected>}/>
      <Route path="/findings" element={<Protected><Findings/></Protected>}/>
      <Route path="/findings/:id" element={<Protected><FindingDetail/></Protected>}/>
      <Route path="/assets" element={<Protected><Assets/></Protected>}/>
      <Route path="/assets/:id" element={<Protected><AssetDetail/></Protected>}/>
      <Route path="/products" element={<Protected><Products/></Protected>}/>
      <Route path="/products/:id" element={<Protected><ProductDetail/></Protected>}/>
      <Route path="/engagements" element={<Protected><Engagements/></Protected>}/>
      <Route path="/tickets" element={<Protected><Tickets/></Protected>}/>
      <Route path="/exceptions" element={<Protected><Exceptions/></Protected>}/>
      <Route path="/exceptions/new" element={<Protected><RequestRiskAcceptance/></Protected>}/>
      <Route path="/exceptions/:id" element={<Protected><ExceptionDetail/></Protected>}/>
      <Route path="/admin/approval-routing" element={<Protected><ApprovalRouting/></Protected>}/>
      <Route path="/integrations" element={<Protected><Integrations/></Protected>}/>
      <Route path="/imports" element={<Protected><ImportJobs/></Protected>}/>
      <Route path="/reports" element={<Protected><Reports/></Protected>}/>
      <Route path="/admin" element={<Protected><Admin/></Protected>}/>
      <Route path="/operational" element={<Protected><Operational/></Protected>}/>
      <Route path="/attack-paths" element={<Protected><AttackPaths/></Protected>}/>
      <Route path="/admin/tls-certs" element={<Protected><TlsCerts/></Protected>}/>
      <Route path="/admin/sbom" element={<Protected><SbomUpload/></Protected>}/>
      <Route path="/admin/yara" element={<Protected><Yara/></Protected>}/>
      <Route path="/easm" element={<Protected><Easm/></Protected>}/>
      <Route path="/compliance" element={<Protected><Compliance/></Protected>}/>
      <Route path="/admin/chatops" element={<Protected><ChatOps/></Protected>}/>
      <Route path="/admin/health" element={<Protected><OpsHealth/></Protected>}/>
      <Route path="/admin/backups" element={<Protected><Backups/></Protected>}/>
      <Route path="/admin/audit-log" element={<Protected><AuditLog/></Protected>}/>
      <Route path="/admin/assignment-rules" element={<Protected><AssignmentRules/></Protected>}/>
      <Route path="/admin/ownership" element={<Protected><OwnershipMappings/></Protected>}/>
      <Route path="/admin/sla-policies" element={<Protected><SlaPolicies/></Protected>}/>
      <Route path="/admin/playbooks" element={<Protected><Playbooks/></Protected>}/>
      <Route path="/admin/playbooks/:id" element={<Protected><PlaybookDetail/></Protected>}/>
      <Route path="/automation" element={<Protected><Automation/></Protected>}/>
      <Route path="/exposure" element={<Protected><Exposure/></Protected>}/>
      <Route path="/admin/nmap-scans" element={<Protected><NmapUpload/></Protected>}/>
      <Route path="/admin/nikto-scans" element={<Protected><NiktoScans/></Protected>}/>
      <Route path="/admin/recon-osint" element={<Protected><ReconOSINT/></Protected>}/>
      <Route path="/admin/criticality-scoring" element={<Protected><CriticalityScoring/></Protected>}/>
      <Route path="/admin/web-scans" element={<Protected><WebScansUpload/></Protected>}/>
      <Route path="/admin/users" element={<Protected><Users/></Protected>}/>
      <Route path="/admin/teams" element={<Protected><Teams/></Protected>}/>
      <Route path="/admin/notifications" element={<Protected><Notifications/></Protected>}/>
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
