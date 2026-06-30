import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";
import { Toaster } from "@/components/ui/sonner";
import "@/index.css";

import Login from "@/pages/Login";
import AuthCallback from "@/pages/AuthCallback";
import Dashboard from "@/pages/Dashboard";
import Findings from "@/pages/Findings";
import FindingDetail from "@/pages/FindingDetail";
import { Assets, AssetDetail } from "@/pages/Assets";
import { Products, Engagements, Tickets, Exceptions } from "@/pages/Operations";
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
      <Route path="/integrations" element={<Protected><Integrations/></Protected>}/>
      <Route path="/imports" element={<Protected><ImportJobs/></Protected>}/>
      <Route path="/reports" element={<Protected><Reports/></Protected>}/>
      <Route path="/admin" element={<Protected><Admin/></Protected>}/>
      <Route path="/operational" element={<Protected><Operational/></Protected>}/>
      <Route path="/attack-paths" element={<Protected><AttackPaths/></Protected>}/>
      <Route path="/admin/assignment-rules" element={<Protected><AssignmentRules/></Protected>}/>
      <Route path="/admin/ownership" element={<Protected><OwnershipMappings/></Protected>}/>
      <Route path="/admin/sla-policies" element={<Protected><SlaPolicies/></Protected>}/>
      <Route path="/admin/web-scans" element={<Protected><WebScansUpload/></Protected>}/>
      <Route path="/admin/users" element={<Protected><Users/></Protected>}/>
      <Route path="/admin/notifications" element={<Protected><Notifications/></Protected>}/>
    </Routes>
  );
};

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <AppRouter/>
      </BrowserRouter>
      <Toaster richColors position="top-right" />
    </AuthProvider>
  );
}
