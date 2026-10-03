import { FindingsView } from "../components/FindingsView";
import { Page, PageHeader } from "../components/ui";

export function FindingsPage() {
  return (
    <Page>
      <PageHeader
        title="Findings"
        description="Deduplicated results across every scan, with detection state and analyst dispositions."
      />
      <FindingsView />
    </Page>
  );
}
