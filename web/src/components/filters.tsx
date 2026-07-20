import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useState, type KeyboardEvent } from "react";
import { cn } from "./ui";

const triggerCls =
  "inline-flex items-center gap-1.5 rounded-md border border-neutral-300 bg-white px-3 py-1.5 text-sm font-medium text-neutral-700 hover:bg-neutral-50 dark:border-neutral-700 dark:bg-neutral-800 dark:text-neutral-200 dark:hover:bg-neutral-700";
const contentCls =
  "z-50 max-h-72 min-w-44 overflow-y-auto rounded-md border border-neutral-200 bg-white p-1 shadow-lg dark:border-neutral-800 dark:bg-neutral-900";
const itemCls =
  "flex cursor-pointer items-center gap-2 rounded px-2 py-1.5 text-sm outline-none hover:bg-neutral-100 dark:hover:bg-neutral-800";

export interface Option {
  value: string;
  label: string;
}

/** MultiSelect is a dropdown of checkboxes for picking several values from a
 *  fixed set. The trigger shows the label plus a count when anything is selected;
 *  the menu stays open across picks so you can select several at once. */
export function MultiSelect({
  label,
  options,
  selected,
  onChange,
  className,
}: {
  label: string;
  options: Option[];
  selected: string[];
  onChange: (next: string[]) => void;
  className?: string;
}) {
  const toggle = (v: string) =>
    onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v]);

  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <button type="button" className={cn(triggerCls, selected.length > 0 && "border-indigo-400 dark:border-indigo-600", className)}>
          <span>{label}</span>
          {selected.length > 0 && (
            <span className="rounded bg-indigo-100 px-1.5 text-xs font-semibold text-indigo-700 dark:bg-indigo-950 dark:text-indigo-300">
              {selected.length}
            </span>
          )}
          <span className="text-neutral-400">▾</span>
        </button>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="start" sideOffset={4} className={contentCls}>
          {options.map((o) => (
            <DropdownMenu.CheckboxItem
              key={o.value}
              checked={selected.includes(o.value)}
              // Keep the menu open so several boxes can be ticked in one go.
              onSelect={(e) => e.preventDefault()}
              onCheckedChange={() => toggle(o.value)}
              className={itemCls}
            >
              <span className="flex h-4 w-4 items-center justify-center rounded border border-neutral-300 text-[10px] dark:border-neutral-600">
                {selected.includes(o.value) ? "✓" : ""}
              </span>
              <span>{o.label}</span>
            </DropdownMenu.CheckboxItem>
          ))}
          {selected.length > 0 && (
            <>
              <DropdownMenu.Separator className="my-1 h-px bg-neutral-200 dark:bg-neutral-800" />
              <DropdownMenu.Item
                onSelect={() => onChange([])}
                className={cn(itemCls, "text-neutral-500")}
              >
                Clear
              </DropdownMenu.Item>
            </>
          )}
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

/** TokenInput collects several free-text values as chips — for open-ended fields
 *  (host, CVE, tag) where the set isn't enumerable. Enter or comma commits the
 *  draft; Backspace on an empty box removes the last chip. Any-of semantics. */
export function TokenInput({
  values,
  onChange,
  placeholder,
  className,
}: {
  values: string[];
  onChange: (next: string[]) => void;
  placeholder?: string;
  className?: string;
}) {
  const [draft, setDraft] = useState("");

  const add = (raw: string) => {
    const v = raw.trim().replace(/,$/, "").trim();
    if (v && !values.includes(v)) onChange([...values, v]);
    setDraft("");
  };
  const removeAt = (i: number) => onChange(values.filter((_, j) => j !== i));

  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      add(draft);
    } else if (e.key === "Backspace" && draft === "" && values.length > 0) {
      removeAt(values.length - 1);
    }
  };

  return (
    <div
      className={cn(
        "flex min-h-[34px] flex-wrap items-center gap-1 rounded-md border border-neutral-300 bg-white px-1.5 py-1 dark:border-neutral-700 dark:bg-neutral-800",
        className,
      )}
    >
      {values.map((v, i) => (
        <span
          key={v}
          className="inline-flex items-center gap-1 rounded bg-neutral-100 px-1.5 py-0.5 text-xs dark:bg-neutral-700"
        >
          {v}
          <button
            type="button"
            onClick={() => removeAt(i)}
            className="text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200"
            aria-label={`Remove ${v}`}
          >
            ×
          </button>
        </span>
      ))}
      <input
        value={draft}
        onChange={(e) => setDraft(e.target.value)}
        onKeyDown={onKeyDown}
        onBlur={() => draft && add(draft)}
        placeholder={values.length === 0 ? placeholder : ""}
        className="min-w-[6rem] flex-1 bg-transparent px-1 text-sm outline-none placeholder:text-neutral-400"
      />
    </div>
  );
}
