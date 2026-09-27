import {
  DISPOSITION_LABELS,
  DISPOSITIONS,
  EFFECTIVE_STATES,
  SEVERITIES,
  STATE_LABELS,
  type FindingQuery,
} from "../api";
import { MultiSelect, TokenInput, type Option } from "./filters";
import { Button, Input, Select } from "./ui";

type ValueKind = "enum" | "tags" | "text" | "time" | "number" | "boolean";

interface FieldDef {
  value: string;
  label: string;
  kind: ValueKind;
  ops: string[];
  options?: Option[]; // for kind "enum" (target is filled dynamically)
}

const SEVERITY_OPTS: Option[] = SEVERITIES.map((s) => ({ value: s, label: s.toUpperCase() }));
const STATE_OPTS: Option[] = EFFECTIVE_STATES.map((s) => ({ value: s, label: STATE_LABELS[s] }));
const DISPOSITION_OPTS: Option[] = DISPOSITIONS.map((d) => ({ value: d, label: DISPOSITION_LABELS[d] }));
// Nuclei result protocols. The backend matches `type` case-insensitively, so the
// picker stores the canonical lowercase value.
const TYPE_OPTS: Option[] = [
  "http",
  "dns",
  "tcp",
  "network",
  "ssl",
  "websocket",
  "whois",
  "file",
  "headless",
  "code",
  "javascript",
].map((t) => ({ value: t, label: t }));

const FIELDS: FieldDef[] = [
  { value: "name", label: "Name / template", kind: "text", ops: ["contains", "not_contains", "starts_with", "is_empty", "is_not_empty"] },
  { value: "severity", label: "Severity", kind: "enum", ops: ["any_of", "none_of"], options: SEVERITY_OPTS },
  { value: "state", label: "State", kind: "enum", ops: ["any_of", "none_of"], options: STATE_OPTS },
  { value: "disposition", label: "Disposition", kind: "enum", ops: ["any_of", "none_of"], options: DISPOSITION_OPTS },
  { value: "target", label: "Target", kind: "enum", ops: ["any_of", "none_of"] },
  { value: "host", label: "Host", kind: "text", ops: ["contains", "not_contains", "starts_with", "is_empty", "is_not_empty"] },
  { value: "matcher", label: "Matcher", kind: "text", ops: ["contains", "not_contains", "starts_with", "is_empty", "is_not_empty"] },
  { value: "extracted_result", label: "Extracted result", kind: "text", ops: ["contains", "not_contains", "is_empty", "is_not_empty"] },
  { value: "matched_at", label: "Matched at", kind: "text", ops: ["contains", "not_contains", "starts_with", "is_empty", "is_not_empty"] },
  { value: "type", label: "Type", kind: "enum", ops: ["any_of", "none_of"], options: TYPE_OPTS },
  { value: "first_seen_at", label: "First seen", kind: "time", ops: ["after", "before", "between"] },
  { value: "last_seen_at", label: "Last seen", kind: "time", ops: ["after", "before", "between"] },
  { value: "cve", label: "CVE", kind: "text", ops: ["contains", "not_contains", "is_empty", "is_not_empty"] },
  { value: "tag", label: "Tag", kind: "tags", ops: ["any_of", "none_of", "is_empty", "is_not_empty"] },
  { value: "recast_severity", label: "Recast severity", kind: "enum", ops: ["any_of", "none_of", "is_empty", "is_not_empty"], options: SEVERITY_OPTS },
  { value: "observed_severity", label: "Observed severity", kind: "enum", ops: ["any_of", "none_of"], options: SEVERITY_OPTS },
  { value: "accept_expires_at", label: "Accept expires", kind: "time", ops: ["after", "before", "between"] },
  { value: "times_mitigated", label: "Times mitigated", kind: "number", ops: ["gte", "gt", "eq", "neq", "lt", "lte"] },
  { value: "occurrence_count", label: "Occurrence count", kind: "number", ops: ["gt", "gte", "eq", "neq", "lt", "lte"] },
  { value: "auto_mitigation_eligible", label: "Auto-mitigation", kind: "boolean", ops: ["is", "is_not"] },
];

const BOOL_OPTS: Option[] = [
  { value: "true", label: "yes" },
  { value: "false", label: "no" },
];

const OP_LABEL: Record<string, string> = {
  any_of: "is one of",
  none_of: "is not one of",
  contains: "contains",
  not_contains: "does not contain",
  starts_with: "starts with",
  is_empty: "is empty",
  is_not_empty: "is not empty",
  after: "after",
  before: "before",
  between: "between",
  eq: "equals",
  neq: "does not equal",
  gt: "greater than",
  gte: "at least",
  lt: "less than",
  lte: "at most",
  is: "is",
  is_not: "is not",
};

const fieldDef = (f: string) => FIELDS.find((x) => x.value === f) ?? FIELDS[0];
const opNeedsValue = (op: string) => op !== "is_empty" && op !== "is_not_empty";
const isSingleDateOp = (op: string) => op === "before" || op === "after";
function rowComplete(r: Row): boolean {
  if (!opNeedsValue(r.op)) return true;
  if (r.op === "between") return Boolean(r.values[0]?.trim()) && Boolean(r.values[1]?.trim());
  if (isSingleDateOp(r.op)) return Boolean(r.values[0]?.trim());
  return r.values.some((v) => v.trim() !== "");
}
function queryValues(r: Row): string[] {
  if (isSingleDateOp(r.op)) return [r.values[0].trim()];
  return r.values;
}
function valuesAfterOpChange(op: string, values: string[]): string[] {
  if (!opNeedsValue(op)) return [];
  if (isSingleDateOp(op)) {
    const first = values[0]?.trim() ?? "";
    return first ? [first] : [];
  }
  return values;
}
function dateInputValue(v: string | undefined): string {
  if (!v) return "";
  return /^\d{4}-\d{2}-\d{2}/.test(v) ? v.slice(0, 10) : "";
}

function utcDateOnly(d: Date): string {
  return d.toISOString().slice(0, 10);
}
let rowSeq = 0;

export interface Row {
  id: number;
  connector: "and" | "or";
  field: string;
  op: string;
  values: string[];
}

export function makeRow(partial?: Partial<Row>): Row {
  return { id: ++rowSeq, connector: "and", field: "severity", op: "any_of", values: [], ...partial };
}

/** expiringAcceptancesRows is the "accepted, expiring within 7 days" quick filter. */
export function expiringAcceptancesRows(now = new Date()): Row[] {
  const start = utcDateOnly(now);
  const end = utcDateOnly(new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000));
  return [
    makeRow({ field: "disposition", op: "any_of", values: ["accepted"] }),
    makeRow({ field: "accept_expires_at", op: "between", values: [start, end] }),
  ];
}

/** rowsToQuery compiles the ordered rows into the OR-of-AND grammar: an "or"
 *  connector (on any row after the first) starts a new group; consecutive "and"
 *  rows stay in the current group. Incomplete rows (a value-taking op with no
 *  values) are dropped so a half-built row doesn't filter anything out. */
export function rowsToQuery(rows: Row[]): FindingQuery {
  const groups: { conditions: { field: string; op: string; values?: string[] }[] }[] = [];
  rows.forEach((r, i) => {
    if (!rowComplete(r)) return;
    const cond = opNeedsValue(r.op) ? { field: r.field, op: r.op, values: queryValues(r) } : { field: r.field, op: r.op };
    if (i === 0 || r.connector === "or" || groups.length === 0) groups.push({ conditions: [cond] });
    else groups[groups.length - 1].conditions.push(cond);
  });
  return { groups };
}

/** queryToRows is the inverse of rowsToQuery: it rebuilds editable rows from a
 *  compiled query (each group's first condition after the first gets an "or"
 *  connector). Used to restore the builder from the URL / a shared link. */
export function queryToRows(q: FindingQuery): Row[] {
  const rows: Row[] = [];
  (q.groups ?? []).forEach((g, gi) => {
    (g.conditions ?? []).forEach((c, ci) => {
      rows.push(makeRow({ connector: gi > 0 && ci === 0 ? "or" : "and", field: c.field, op: c.op, values: c.values ?? [] }));
    });
  });
  return rows;
}

function valueText(r: Row, targetOptions: Option[]): string {
  const def = fieldDef(r.field);
  if (!opNeedsValue(r.op)) return "";
  if (def.kind === "enum" || def.kind === "boolean") {
    const opts = def.value === "target" ? targetOptions : def.kind === "boolean" ? BOOL_OPTS : (def.options ?? []);
    return r.values.map((v) => opts.find((o) => o.value === v)?.label ?? v).join(", ");
  }
  return r.values.join(", ");
}

export interface Crumb {
  connector: string;
  field: string;
  op: string;
  value: string;
}

/** rowsToCrumbs renders the active rows as a readable breadcrumb of the filter —
 *  shown even when the builder is collapsed so the active filter stays visible. */
export function rowsToCrumbs(rows: Row[], targetOptions: Option[]): Crumb[] {
  return rows
    .filter((r) => rowComplete(r))
    .map((r, i) => ({
      connector: i === 0 ? "" : r.connector,
      field: fieldDef(r.field).label,
      op: OP_LABEL[r.op],
      value: valueText(r, targetOptions),
    }));
}

/** countActiveConditions is how many complete conditions the filter has (drives
 *  the funnel-icon badge). */
export function countActiveConditions(rows: Row[]): number {
  return rows.filter((r) => rowComplete(r)).length;
}

/** ConditionBuilder is a ServiceNow-style filter: rows of field / operator /
 *  value combined with and/or. Controlled — the parent owns the rows (so they
 *  survive the builder being collapsed) and reads the compiled query via
 *  rowsToQuery. */
export function ConditionBuilder({
  rows,
  onChange,
  targetOptions,
}: {
  rows: Row[];
  onChange: (rows: Row[]) => void;
  targetOptions: Option[];
}) {
  const optionsFor = (def: FieldDef) => (def.value === "target" ? targetOptions : (def.options ?? []));

  const setRow = (id: number, patch: Partial<Row>) =>
    onChange(
      rows.map((r) => {
        if (r.id !== id) return r;
        const merged = { ...r, ...patch };
        // Changing the field resets op + values to that field's defaults.
        if (patch.field && patch.field !== r.field) {
          merged.op = fieldDef(patch.field).ops[0];
          merged.values = [];
        }
        // Changing to/from a no-value op clears stale values. Switching a
        // filled `between` row to `before`/`after` must drop the second date
        // so compileTimeCondition receives exactly one value.
        if (patch.op) merged.values = valuesAfterOpChange(patch.op, merged.values);
        return merged;
      }),
    );

  const addRow = () => onChange([...rows, makeRow()]);
  const removeRow = (id: number) => onChange(rows.filter((r) => r.id !== id));
  const clearAll = () => onChange([]);

  return (
    <div>
      <div className="space-y-2">
        {rows.map((r, i) => {
          const def = fieldDef(r.field);
          return (
            <div key={r.id} className="flex flex-wrap items-center gap-2">
              <div className="w-16 shrink-0 text-right text-xs">
                {i === 0 ? (
                  <span className="text-neutral-400">where</span>
                ) : (
                  <Select
                    value={r.connector}
                    onChange={(e) => setRow(r.id, { connector: e.target.value as "and" | "or" })}
                    className="w-full"
                  >
                    <option value="and">and</option>
                    <option value="or">or</option>
                  </Select>
                )}
              </div>

              <Select value={r.field} onChange={(e) => setRow(r.id, { field: e.target.value })} className="w-48">
                {FIELDS.map((f) => (
                  <option key={f.value} value={f.value}>
                    {f.label}
                  </option>
                ))}
              </Select>

              <Select value={r.op} onChange={(e) => setRow(r.id, { op: e.target.value })} className="w-36">
                {def.ops.map((op) => (
                  <option key={op} value={op}>
                    {OP_LABEL[op]}
                  </option>
                ))}
              </Select>

              <div className="min-w-[12rem] flex-1">
                {!opNeedsValue(r.op) ? (
                  <span className="text-sm text-neutral-400">—</span>
                ) : def.kind === "enum" ? (
                  <MultiSelect
                    label="Select…"
                    options={optionsFor(def)}
                    selected={r.values}
                    onChange={(vals) => setRow(r.id, { values: vals })}
                  />
                ) : def.kind === "tags" ? (
                  <TokenInput values={r.values} onChange={(vals) => setRow(r.id, { values: vals })} placeholder="add value…" />
                ) : def.kind === "boolean" ? (
                  <Select
                    value={r.values[0] ?? ""}
                    onChange={(e) => setRow(r.id, { values: e.target.value ? [e.target.value] : [] })}
                    className="w-28 shrink-0"
                    aria-label="Boolean value"
                  >
                    <option value="">Select…</option>
                    {BOOL_OPTS.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </Select>
                ) : def.kind === "number" ? (
                  <Input
                    type="number"
                    step={1}
                    value={r.values[0] ?? ""}
                    onChange={(e) => setRow(r.id, { values: e.target.value.trim() ? [e.target.value.trim()] : [] })}
                    placeholder="number…"
                    className="w-24 shrink-0 tabular-nums"
                  />
                ) : def.kind === "time" ? (
                  <div className="flex flex-nowrap items-center gap-2">
                    <label className="flex shrink-0 items-center gap-1.5">
                      {r.op === "between" ? (
                        <span className="text-xs text-neutral-500">From</span>
                      ) : null}
                      <Input
                        type="date"
                        value={dateInputValue(r.values[0])}
                        onChange={(e) =>
                          setRow(r.id, { values: r.op === "between" ? [e.target.value, r.values[1] ?? ""] : e.target.value ? [e.target.value] : [] })
                        }
                        aria-label={r.op === "between" ? "From date" : "Date"}
                        className="w-40 shrink-0"
                      />
                    </label>
                    {r.op === "between" && (
                      <>
                        <span className="shrink-0 text-xs text-neutral-400">and</span>
                        <label className="flex shrink-0 items-center gap-1.5">
                          <span className="text-xs text-neutral-500">To</span>
                          <Input
                            type="date"
                            value={dateInputValue(r.values[1])}
                            onChange={(e) => setRow(r.id, { values: [r.values[0] ?? "", e.target.value] })}
                            aria-label="To date"
                            className="w-40 shrink-0"
                          />
                        </label>
                      </>
                    )}
                  </div>
                ) : (
                  <Input
                    value={r.values[0] ?? ""}
                    onChange={(e) => setRow(r.id, { values: e.target.value ? [e.target.value] : [] })}
                    placeholder="value…"
                    className="w-full"
                  />
                )}
              </div>

              <Button variant="ghost" aria-label="Remove condition" onClick={() => removeRow(r.id)} className="px-2 text-neutral-500">
                ✕
              </Button>
            </div>
          );
        })}
      </div>

      <div className="mt-3 flex items-center gap-2">
        <Button variant="ghost" onClick={addRow} className="text-sm text-indigo-600 dark:text-indigo-400">
          + Add condition
        </Button>
        {rows.length > 0 && (
          <Button variant="ghost" onClick={clearAll} className="text-sm text-neutral-500">
            Clear all
          </Button>
        )}
      </div>
    </div>
  );
}
