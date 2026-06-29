import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "@/lib/auth";
import { Toaster } from "@/components/ui/sonner";
import "@/index.css";

import Login from "@/pages/Login";
import Dashboard from "@/pages/Dashboard";
import Findings from "@/pages/Findings";
import FindingDetail from "@/pages/FindingDetail";
import { Assets, AssetDetail } from "@/pages/Assets";
import { Products, Engagements, Tickets, Exceptions } from "@/pages/Operations";
import ProductDetail from "@/pages/ProductDetail";
import { Integrations, ImportJobs, Reports, Admin } from "@/pages/AdminAndIntegrations";

const Protected = ({ children }) => {
  const { user, loading } = useAuth();
  if (loading) return <div className="min-h-screen flex items-center justify-center bg-[#090C10] text-slate-500">Loading…</div>;
  if (!user) return <Navigate to="/login" replace />;
  return children;
};

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login/>}/>
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
        </Routes>
      </BrowserRouter>
      <Toaster richColors position="top-right" />
    </AuthProvider>
  );
}
