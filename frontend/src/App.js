import "@/App.css";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { Toaster } from "@/components/ui/sonner";
import { DashboardLayout } from "@/components/DashboardLayout";

import Landing from "@/pages/Landing";
import Dashboard from "@/pages/Dashboard";
import WebAppTesting from "@/pages/WebAppTesting";
import MobileTesting from "@/pages/MobileTesting";
import CodeReview from "@/pages/CodeReview";
import SCA from "@/pages/SCA";
import Scanner from "@/pages/Scanner";
import AIPentest from "@/pages/AIPentest";
import AgentDesk from "@/pages/AgentDesk";
import OSINT from "@/pages/OSINT";
import RedTeam from "@/pages/RedTeam";
import Toolkit from "@/pages/Toolkit";
import DeviceBridge from "@/pages/DeviceBridge";
import ADEnum from "@/pages/ADEnum";
import NetworkMap from "@/pages/NetworkMap";
import BinRE from "@/pages/BinRE";
import OperationReport from "@/pages/OperationReport";
import Findings from "@/pages/Findings";
import BugBounty from "@/pages/BugBounty";
import Guide from "@/pages/Guide";
import GestureControl from "@/pages/GestureControl";
import ReconLab from "@/pages/ReconLab";
import CryptoLab from "@/pages/CryptoLab";
import WebInspector from "@/pages/WebInspector";
import Settings from "@/pages/Settings";
import Arsenal from "@/pages/Arsenal";
import VulnSuite from "@/pages/VulnSuite";
import AIAgent from "@/pages/AIAgent";
import Playbooks from "@/pages/Playbooks";
import SOC from "@/pages/SOC";
import Assessment from "@/pages/Assessment";
import ProxyChain from "@/pages/ProxyChain";
import KillChain from "@/pages/KillChain";
import Legal from "@/pages/Legal";
import AllTools from "@/pages/AllTools";
import Login from "@/pages/Login";
import { ProtectedRoute } from "@/components/ProtectedRoute";

function App() {
  return (
    <div className="App">
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route path="/login" element={<Login />} />
          <Route path="/app" element={<ProtectedRoute><DashboardLayout /></ProtectedRoute>}>
            <Route index element={<Dashboard />} />
            <Route path="web" element={<WebAppTesting />} />
            <Route path="mobile" element={<MobileTesting />} />
            <Route path="code-review" element={<CodeReview />} />
            <Route path="sca" element={<SCA />} />
            <Route path="scanner" element={<Scanner />} />
            <Route path="osint" element={<OSINT />} />
            <Route path="redteam" element={<RedTeam />} />
            <Route path="ad-enum" element={<ADEnum />} />
            <Route path="netmap" element={<NetworkMap />} />
            <Route path="binre" element={<BinRE />} />
            <Route path="operation" element={<OperationReport />} />
            <Route path="findings" element={<Findings />} />
            <Route path="bugbounty" element={<BugBounty />} />
            <Route path="toolkit" element={<Toolkit />} />
            <Route path="device" element={<DeviceBridge />} />
            <Route path="ai-pentest" element={<AIPentest />} />
            <Route path="agents" element={<AgentDesk />} />
            <Route path="guide" element={<Guide />} />
            <Route path="gesture" element={<GestureControl />} />
            <Route path="recon" element={<ReconLab />} />
            <Route path="crypto" element={<CryptoLab />} />
            <Route path="web-inspect" element={<WebInspector />} />
            <Route path="settings" element={<Settings />} />
            <Route path="arsenal" element={<Arsenal />} />
            <Route path="vuln-suite" element={<VulnSuite />} />
            <Route path="ai-agent" element={<AIAgent />} />
            <Route path="playbooks" element={<Playbooks />} />
            <Route path="vapt" element={<Assessment kind="vapt" />} />
            <Route path="wapt" element={<Assessment kind="wapt" />} />
            <Route path="soc" element={<SOC />} />
            <Route path="proxy-chain" element={<ProxyChain />} />
            <Route path="kill-chain" element={<KillChain />} />
            <Route path="legal" element={<Legal />} />
            <Route path="all-tools" element={<AllTools />} />
          </Route>
        </Routes>
      </BrowserRouter>
      <Toaster theme="dark" position="top-right" richColors />
    </div>
  );
}

export default App;
