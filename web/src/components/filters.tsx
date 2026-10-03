import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { useState, type KeyboardEvent } from "react";
import { buttonClass, cn, focusRing, menuContentClass, menuItemClass, menuSeparatorClass } from "./ui";

const contentCls = cn(menuContentClass, "max-h-72 overflow-y-auto");
const itemCls = menuItemClass;

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
        <button type="button" className={cn(buttonClass("secondary", "md", selected.length > 0), className)}>
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
              <DropdownMenu.Separator className={menuSeparatorClass} />
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
        "flex min-h-9 flex-wrap items-center gap-1 rounded-md border border-neutral-300 bg-white px-1.5 py-1 focus-within:border-indigo-500 focus-within:ring-1 focus-within:ring-indigo-500 dark:border-neutral-700 dark:bg-neutral-800",
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
            className={cn("rounded-sm text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200", focusRing)}
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
