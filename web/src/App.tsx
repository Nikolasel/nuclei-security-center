import { Navigate, Route, Routes } from "react-router-dom";
import { useMe } from "./auth";
import { Brand } from "./components/Brand";
import { Layout } from "./components/Layout";
import { Button, ErrorText, Spinner } from "./components/ui";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { NodesPage } from "./pages/NodesPage";
import { ScanPoliciesPage } from "./pages/ScanPoliciesPage";
import { ScansPage } from "./pages/ScansPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { SchedulesPage } from "./pages/SchedulesPage";
import { ServiceAccountsPage } from "./pages/ServiceAccountsPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TargetsPage } from "./pages/TargetsPage";
import { TemplateSetsPage } from "./pages/TemplateSetsPage";
import { TemplatesPage } from "./pages/TemplatesPage";

function LoginScreen() {
  return (
    <div className="relative flex min-h-screen items-center justify-center overflow-hidden bg-slate-950 px-4">
      <div className="pointer-events-none absolute inset-0 bg-[radial-gradient(circle_at_50%_35%,rgba(34,211,238,0.18),transparent_32%),radial-gradient(circle_at_75%_75%,rgba(139,92,246,0.17),transparent_30%)]" />
      <div className="relative w-[min(92vw,25rem)] rounded-lg border border-cyan-200/20 bg-slate-950/85 p-8 text-center shadow-[0_0_55px_rgba(34,211,238,0.14)] backdrop-blur">
        <Brand compact className="justify-center" />
        <h1 className="mt-5 text-xl font-semibold text-white">Nuclei Security Center</h1>
        <p className="mt-2 text-sm text-slate-300">Sign in with your organization account.</p>
        <a href="/api/auth/login" className="mt-6 inline-block">
          <Button variant="primary">Log in</Button>
        </a>
      </div>
    </div>
  );
}

export default function App() {
  const me = useMe();

  if (me.isLoading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Spinner />
      </div>
    );
  }
  if (me.isError) {
    return (
      <div className="mx-auto max-w-lg p-8">
        <ErrorText error={me.error} />
      </div>
    );
  }
  if (!me.data) return <LoginScreen />;

  return (
    <Layout identity={me.data}>
      <Routes>
        <Route path="/" element={<Navigate to="/findings" replace />} />
        <Route path="/findings" element={<FindingsPage />} />
        <Route path="/findings/:id" element={<FindingDetailPage />} />
        <Route path="/scans" element={<ScansPage />} />
        <Route path="/scans/:id" element={<ScanDetailPage />} />
        <Route path="/schedules" element={<SchedulesPage />} />
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/templates" element={<TemplatesPage />} />
        <Route path="/template-sets" element={<TemplateSetsPage />} />
        <Route path="/scan-policies" element={<ScanPoliciesPage />} />
        <Route path="/nodes" element={<NodesPage />} />
        <Route path="/service-accounts" element={<ServiceAccountsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/findings" replace />} />
      </Routes>
    </Layout>
  );
}
