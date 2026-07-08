import { useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { FindingsView } from "../components/FindingsView";
import { ErrorText, Spinner } from "../components/ui";

export function FindingsPage() {
  const q = useQuery({ queryKey: ["findings"], queryFn: () => api.listFindings() });

  return (
    <div className="space-y-4">
      <h1 className="text-xl font-semibold">Findings</h1>
      {q.isLoading ? (
        <Spinner />
      ) : q.isError ? (
        <ErrorText error={q.error} />
      ) : (
        <FindingsView findings={q.data ?? []} />
      )}
    </div>
  );
}
