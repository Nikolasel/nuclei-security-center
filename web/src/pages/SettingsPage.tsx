import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, type EnvVariable } from "../api";
import { hasRole, useMe } from "../auth";
import { Button, Card, ErrorText, Field, Input, Spinner } from "../components/ui";

function groupEnvVariables(vars: EnvVariable[]): { group: string; items: EnvVariable[] }[] {
  const order: string[] = [];
  const map = new Map<string, EnvVariable[]>();
  for (const v of vars) {
    const list = map.get(v.group);
    if (!list) {
      order.push(v.group);
      map.set(v.group, [v]);
    } else {
      list.push(v);
    }
  }
  return order.map((group) => ({ group, items: map.get(group) ?? [] }));
}

function effectiveDisplay(v: EnvVariable): string {
  if (v.effective != null && v.effective !== "") return v.effective;
  if (v.sensitive) return v.set ? "hidden" : "—";
  if (v.effective === "") return "(empty)";
  return "—";
}

export function SettingsPage() {
  const me = useMe();
  const isAdmin = hasRole(me.data ?? undefined, "admin");
  const qc = useQueryClient();

  const settings = useQuery({
    queryKey: ["settings"],
    queryFn: () => api.getSettings(),
    enabled: isAdmin,
  });

  const environment = useQuery({
    queryKey: ["settings", "environment"],
    queryFn: () => api.getEnvironment(),
    enabled: isAdmin,
  });

  const [enabled, setEnabled] = useState(false);
  const [days, setDays] = useState("");
  const [includeAdhoc, setIncludeAdhoc] = useState(false);

  // Seed the form from the server once it loads; re-seed whenever the fetched
  // record changes (e.g. after a save invalidates and refetches).
  useEffect(() => {
    if (settings.data) {
      setEnabled(settings.data.retention_enabled);
      setDays(settings.data.scan_retention_days != null ? String(settings.data.scan_retention_days) : "");
      setIncludeAdhoc(settings.data.retention_include_adhoc);
    }
  }, [settings.data]);

  const daysNum = Number(days);
  const daysValid = days.trim() !== "" && Number.isInteger(daysNum) && daysNum > 0 && daysNum <= 36500;
  // Enabling retention requires a valid window; disabled retention may leave the
  // window blank (it's simply ignored until re-enabled).
  const invalid = enabled && !daysValid;

  const save = useMutation({
    mutationFn: () =>
      api.updateSettings({
        retention_enabled: enabled,
        scan_retention_days: daysValid ? daysNum : null,
        retention_include_adhoc: includeAdhoc,
      }),
    onSuccess: () => void qc.invalidateQueries({ queryKey: ["settings"] }),
  });

  if (!isAdmin) {
    return (
      <div className="space-y-4">
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="text-sm text-neutral-500">Settings are available to administrators only.</p>
      </div>
    );
  }

  return (
    <div className="max-w-4xl space-y-5">
      <div>
        <h1 className="text-xl font-semibold">Settings</h1>
        <p className="mt-1 text-sm text-neutral-500">Global configuration for this Nuclei Security Center.</p>
      </div>

      {settings.isLoading ? (
        <Spinner />
      ) : settings.isError ? (
        <ErrorText error={settings.error} />
      ) : (
        <Card className="space-y-4 p-5">
          <div>
            <h2 className="text-sm font-semibold">Scan retention</h2>
            <p className="mt-1 text-sm text-neutral-500">
              Automatically delete scans (and their findings occurrences and archived output) older than a
              set number of days. Each target&apos;s most recent scan is always kept. Deletion is
              evidence-preserving — a finding&apos;s lifecycle is recomputed from the scans that remain.
            </p>
          </div>

          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
              className="h-4 w-4 rounded border-neutral-300 dark:border-neutral-700"
            />
            Enable automatic scan deletion
          </label>

          <Field label="Delete scans older than (days)">
            <Input
              type="number"
              min={1}
              max={36500}
              value={days}
              disabled={!enabled}
              placeholder="e.g. 90"
              onChange={(e) => setDays(e.target.value)}
              className="w-full max-w-[12rem]"
            />
          </Field>
          {enabled && !daysValid && (
            <p className="-mt-2 text-xs text-amber-700 dark:text-amber-400">
              Enter a whole number between 1 and 36500.
            </p>
          )}

          <label className="flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={includeAdhoc}
              disabled={!enabled}
              onChange={(e) => setIncludeAdhoc(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-neutral-300 dark:border-neutral-700"
            />
            <span>
              Also delete ad-hoc scans (not tied to a target)
              <span className="mt-0.5 block text-xs text-neutral-500">
                Ad-hoc scans have no target history to anchor, so when included they&apos;re deleted purely
                on age. Off by default — only target-linked scans are swept.
              </span>
            </span>
          </label>

          {save.isError && <ErrorText error={save.error} />}

          <div className="flex items-center gap-3">
            <Button variant="primary" disabled={invalid || save.isPending} onClick={() => save.mutate()}>
              {save.isPending ? "Saving…" : "Save"}
            </Button>
            {settings.data?.updated_at && (
              <span className="text-xs text-neutral-400">
                Last updated {new Date(settings.data.updated_at).toLocaleString()}
                {settings.data.updated_by ? ` by ${settings.data.updated_by}` : ""}
              </span>
            )}
          </div>
        </Card>
      )}

      {environment.isLoading ? (
        <Spinner />
      ) : environment.isError ? (
        <ErrorText error={environment.error} />
      ) : (
        <Card className="space-y-4 p-5">
          <div>
            <h2 className="text-sm font-semibold">Environment configuration</h2>
            <p className="mt-1 text-sm text-neutral-500">
              Read-only view of this backend process&apos;s allowlisted environment. Secrets are never
              shown. Changing a value requires a redeploy or restart — this page cannot edit env.
            </p>
          </div>
          {groupEnvVariables(environment.data?.variables ?? []).map(({ group, items }) => (
            <div key={group}>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-neutral-500">{group}</h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-neutral-200 text-left text-xs uppercase tracking-wide text-neutral-500 dark:border-neutral-800">
                      <th className="px-2 py-1.5 font-medium">Variable</th>
                      <th className="px-2 py-1.5 font-medium">Status</th>
                      <th className="px-2 py-1.5 font-medium">Effective</th>
                      <th className="px-2 py-1.5 font-medium">Default</th>
                    </tr>
                  </thead>
                  <tbody>
                    {items.map((v) => (
                      <tr
                        key={v.name}
                        className="border-b border-neutral-100 last:border-0 dark:border-neutral-800/60"
                      >
                        <td className="px-2 py-1.5 font-mono text-xs">{v.name}</td>
                        <td className="px-2 py-1.5 text-neutral-500">{v.set ? "set" : "unset"}</td>
                        <td className="max-w-xs truncate px-2 py-1.5 font-mono text-xs text-neutral-700 dark:text-neutral-300" title={effectiveDisplay(v)}>
                          {effectiveDisplay(v)}
                        </td>
                        <td className="max-w-xs truncate px-2 py-1.5 font-mono text-xs text-neutral-500" title={v.default || "—"}>
                          {v.default || "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ))}
        </Card>
      )}
    </div>
  );
}
