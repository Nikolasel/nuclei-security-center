import { Navigate, Route, Routes } from "react-router-dom";
import { useMe } from "./auth";
import { Layout } from "./components/Layout";
import { Button, Card, ErrorText, Spinner } from "./components/ui";
import { FindingDetailPage } from "./pages/FindingDetailPage";
import { FindingsPage } from "./pages/FindingsPage";
import { ScansPage } from "./pages/ScansPage";
import { ScanDetailPage } from "./pages/ScanDetailPage";
import { TargetsPage } from "./pages/TargetsPage";
import { TemplateSetsPage } from "./pages/TemplateSetsPage";

function LoginScreen() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-neutral-50 dark:bg-neutral-950">
      <Card className="w-[min(92vw,24rem)] p-8 text-center">
        <h1 className="text-lg font-semibold">Nuclei Security Center</h1>
        <p className="mt-2 text-sm text-neutral-500">Sign in with your organization account.</p>
        <a href="/api/auth/login" className="mt-6 inline-block">
          <Button variant="primary">Log in</Button>
        </a>
      </Card>
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
        <Route path="/targets" element={<TargetsPage />} />
        <Route path="/template-sets" element={<TemplateSetsPage />} />
        <Route path="*" element={<Navigate to="/findings" replace />} />
      </Routes>
    </Layout>
  );
}
