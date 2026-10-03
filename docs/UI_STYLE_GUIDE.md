# UI style guide

How the web app (`web/`) looks and behaves. It is the contract for every screen: when you add or change
a page, compose the primitives in [`web/src/components/ui.tsx`](../web/src/components/ui.tsx) the way
this guide describes, rather than hand-writing Tailwind classes for things that already have a
component. When a pattern you need is missing, add it to `ui.tsx` and document it here in the same
change. Don't introduce a page-local one-off.

The app is an internal, data-dense triage tool. The design goals, in order:

1. **Consistent.** The same action looks and sits the same on every page.
2. **Scannable.** Tables and status badges carry the information; chrome stays quiet.
3. **Safe.** Destructive actions are visually distinct, tucked away, and always confirmed.
4. **Accessible.** Keyboard focus is visible, every control has a name, and both themes reach legible contrast.

## Foundations

### Stack

React + TypeScript + Tailwind CSS v4 (utility classes, no custom CSS beyond `web/src/index.css`),
Radix primitives for dialogs, dropdown menus and tooltips, and `lucide-react` for icons. Don't add
another component library or icon set.

### Color

Colors come from Tailwind's default palette and always carry a role:

| Role | Palette | Used for |
|---|---|---|
| Surface | `neutral` (`bg-neutral-50` page, `bg-white` cards; `neutral-950`/`neutral-900` dark) | Backgrounds, borders, body text |
| Accent | `indigo` | Primary buttons, links, focus rings, selection, active nav, progress |
| Brand | `slate-950` + `cyan`/`violet` glow | **Only** the top header bar, brand mark and login screen |
| Success | `green` / `emerald` | Healthy, complete, enabled, mitigated |
| Warning | `amber` | Caveats, partial results, needs-attention notes |
| Danger | `red` / `rose` | Errors, failures, destructive actions |
| Info | `blue` | Running / in-progress status |
| Severity | `red` → `orange` → `amber` → `yellow` → `sky` | Nuclei severities **only** (critical → info), via `SeverityBadge` |

Rules:

- Every color has a `dark:` counterpart. Use the tokens baked into the primitives, which already pair
  them. Check both themes with the header toggle before you open a PR.
- Muted text is `text-neutral-500`. Placeholders and empty values are `text-neutral-400` (use `<Muted />`).
- Don't use color as the only signal. A badge always has a text label.
- Don't pick a new hue for a new state. Map it onto an existing role.

### Typography

System UI font stack (`index.css`). Base size `text-sm`. The scale is deliberately short:

| Element | Classes | Component |
|---|---|---|
| Page title (one per page) | `text-xl font-semibold tracking-tight` | `PageHeader` |
| Section / card title | `text-sm font-semibold` | `Section`, `FormSection` |
| Dialog title | `text-base font-semibold` | `Modal` |
| Body / table cells | `text-sm` | — |
| Labels, hints, metadata | `text-xs` (`font-medium` for field labels in `Meta`) | `Field`, `Meta`, `FormHint` |
| Table headers, nav group labels | `text-xs uppercase tracking-wide` | `THead` |

- Use `font-mono` for machine values: IDs, hosts, endpoints, template IDs, cron, digests, versions.
- Use `tabular-nums` for counts and numbers that sit in columns.
- Write in sentence case everywhere: titles, buttons, column headers, menu items ("New scan policy",
  not "New Scan Policy"). Nav labels and page titles name the resource and match each other.

### Spacing and layout

- The app shell (`Layout.tsx`) owns the outer gutter (`px-4`), the max width (`96rem`) and the sidebar.
  Pages never add their own outer padding.
- Every routed page's root is `<Page>` (`space-y-5`). Pass `narrow` for form-style pages such as
  Settings (`max-w-4xl`).
- Inside a card: `p-4 sm:p-5` (`Section`). Table cells use `px-4 py-2.5`. Forms stack fields with
  `space-y-4`, and side-by-side fields use `grid gap-4 sm:grid-cols-2`.
- Use `gap-2` between buttons in a row and `gap-3` between larger groups.
- Mobile first: nothing scrolls the page horizontally. Wide content scrolls inside its own container
  (`Table` does this for you). Grids collapse to one column below `sm`.

### Shape, elevation, motion

- `rounded-md` for controls (buttons, inputs, menus, alerts), `rounded-lg` for cards and dialogs,
  `rounded` for badges and tags, `rounded-full` for pills.
- Cards use a 1px `neutral-200` border plus `shadow-sm`. Menus use `shadow-lg`, dialogs `shadow-xl`.
  Nothing else gets a shadow.
- Use only `transition` on hover and focus colors. Animation is reserved for progress (spinner,
  indeterminate bar).

### Icons

`lucide-react`, `h-4 w-4` inline with text (`h-5 w-5` in the header), always `aria-hidden` next to a
text label. An icon-only control must be an `IconButton` with a `label`, which supplies the
accessible name and the tooltip.

## Page anatomy

```
┌ PageHeader ──────────────────────────────────────────────────────────┐
│ ‹ Back link (detail pages only)                                       │
│ Title  [badges]                               [secondary] [Primary]  │
│ One-sentence description of what this page is for.                    │
└───────────────────────────────────────────────────────────────────────┘
  Alert(s): result of the last action, context banners
  Toolbar / filters (Card)
  Content: Card > Table   or   Section, Section, …
  Pager
```

- **`PageHeader` is mandatory.** It holds the title, an optional `description`, optional `badges`
  (status next to the title on detail pages), `actions`, and `back` (`{ label, to }` or
  `{ label, onClick }`) on detail pages.
- **Actions:** at most one primary button per page header, always the **rightmost** item. Secondary
  page actions (Import, Refresh, Download) sit to its left as `secondary` buttons. Group three or more
  related secondary actions into one dropdown (for example "Download ▾" on the scan detail page).
- **List pages:** `PageHeader`, then optional `Alert`, then `Card` › `Table`, then the create/edit `Modal`.
- **Detail pages:** `PageHeader` with `back` + `badges`, then a stack of `Section`s. Lay out
  label/value pairs with `DescriptionList` + `Meta`. Don't hand-roll `<dl>` grids.
- **Admin-only pages** show an `EmptyState` ("X are managed by admins.") to non-admins instead of a
  page whose every call would 403. The backend still enforces this; the UI check is cosmetic.

## Components

### Buttons

`<Button variant size>`. The default is `secondary` / `md`. `md` is `h-9`, the same height as `Input`
and `Select`, so a button lines up with the control beside it.

| Variant | Use for | Rule |
|---|---|---|
| `primary` | The main action of a page or dialog (Save, Run scan, New target) | **One per view.** Rightmost. |
| `secondary` | Every other standalone action (Cancel, Import, Export, Previous/Next) | Default. |
| `ghost` | Low-emphasis actions inside dense UI (inline row actions, toolbar toggles) | Rows and toolbars only. |
| `danger` | The confirm button of a destructive dialog, and destructive actions that *are* a section's purpose ("Revoke all" sessions) | Always behind a confirmation. |
| `danger-ghost` | A visible destructive action in a dense context (Stop scan in a header) | Prefer the `RowActions` menu in tables. |
| `link` | Inline text actions inside prose ("Clear selection", "3 more") | Never for navigation. Use a `<Link className={linkClass}>`. |

- **`size="sm"`** (`h-8`) is for table rows, pagers and card toolbars. Use `md` everywhere else.
- **Label = verb + noun** in sentence case: "New schedule", "Run scan", "Export selected". Avoid bare
  "OK" and "Submit".
- **Pending state:** disable the button and swap the label for the progressive form ("Saving…",
  "Importing…"). Never hide the button.
- **Toggles** (a button that opens a panel) pass `selected` when on, plus `aria-expanded`.
- Never nest a `<Button>` inside an `<a>`. For a link that must look like a button (a file download),
  use `<a className={buttonClass("secondary")}>`.
- Never override a button's colors with `className`. If you need a new look, it is a new variant in `ui.tsx`.

### Links

Use `linkClass` (`text-indigo-600 hover:underline`, focus ring) for navigation to another page or
resource. A react-router `<Link>` for in-app routes, `<a target="_blank" rel="noreferrer">` for
external ones. Links navigate. Buttons act.

### Tables

```tsx
<Card>
  <Table>
    <THead>
      <Th>Name</Th>
      <Th>Hosts</Th>
      <Th aria-label="Actions" />
    </THead>
    <tbody>
      {rows.map((r) => (
        <TRow key={r.id}>
          <Td className="font-medium">{r.name}</Td>
          <Td className="font-mono text-xs">{r.hosts.join(", ")}</Td>
          <RowActions label={r.name} actions={[…]} />
        </TRow>
      ))}
      {rows.length === 0 && <TableEmpty colSpan={3}>No targets yet.</TableEmpty>}
    </tbody>
  </Table>
</Card>
```

- **The first column is the row's identity** (`font-medium`, or a mono ID link).
- **Status vs. properties:** a `Status` column holds only the row's live state as one `Badge`
  (healthy, enabled, complete). Configuration facts (discovery mode, mTLS, source) go in a separate
  `Properties` column rendered with `<PropertyList items={[…]} />`: neutral pills with a
  self-explanatory label ("SYN discovery", not "SYN") and a `title` tooltip explaining the fact.
  A new indicator is one more entry, so it never needs a new column. Hide absent facts with
  `hidden` rather than showing a "no" pill.
- **Empty values** render as `<Muted />` (an em dash) or a muted word ("ad-hoc", "catch-all"). Never
  leave a cell blank.
- **Empty table:** one `TableEmpty` row saying what is missing ("No schedules yet.", or "No findings
  match." when filtered).
- **Clickable rows** pass `onClick` to `TRow` (hover background + pointer). Interactive cells inside
  them stop propagation. `RowActions` does this for you.
- **A toolbar** above a table goes in a `CardHeader` inside the same card.
- **Density:** cells are `px-4 py-2.5`. The one exception is the user-resizable findings grid, which
  keeps `px-3` because its persisted column widths and minimums are tuned to it.
- **Sorting:** a sortable header is a button inside `Th` with `aria-sort` on the `Th`, ↑/↓ for the
  active direction, and a muted ↕ when the column is sortable but inactive.

### Row actions

Every table's trailing cell is `<RowActions actions={[…]} label={rowName} />`:

- Mark **at most two** actions `primary`. They render inline as small ghost buttons. Pick the action
  users reach for most (Edit, View, Run now, Stop).
- Everything else goes in the **"⋯" overflow menu**.
- **Destructive actions** (`danger: true`) always go in the menu, last, red, after a separator. They
  must confirm (see below).
- Role-gated actions pass `hidden: !canDelete` instead of being conditionally spliced in.

### Forms

- Wrap each control in `<Field label hint error required>`. `hint` is help text under the control,
  and `error` is that field's validation message. Don't place a `<p className="-mt-2 …">` after a
  field.
- Controls: `Input`, `Select`, `Textarea` (monospace by default; for hosts, ports, PEM, YAML),
  `Checkbox` (`label` + optional `description`), and `FileInput`. Never style a raw
  `<input>`/`<select>`/`<textarea>`. Width is caller-owned: pass `className="w-full"` in dialogs.
- Group related fields under `FormSection title="…"` (a rule plus a heading), for example
  "Port discovery" or "Notifications".
- **Validation:** validate on the client where cheap (the backend re-validates). Show the message via
  `Field error` and disable the primary button while invalid. Show server errors with `ErrorText`
  right above the dialog's actions.
- A standalone help or caveat line not tied to one field is `FormHint` (`tone="warning"` for caveats).
- Blank means "use the default". Show the default as the placeholder and say so in the hint.

### Dialogs

`<Modal title description size>`, with content in a `space-y-4` stack ending in `<ModalActions>`
(Cancel first, primary rightmost).

- **Sizes:** `default` (simple forms), `wide` (long free-text fields, multi-column knobs), `workspace`
  (full editors such as template-set membership, with a fixed header and footer).
- **Titles** name the operation: "New target", "Edit schedule", "Duplicate scan policy".
- Use `dismissible={false}` only when closing destroys something unrecoverable (a token shown once).

### Confirmations

Never call `window.confirm`. Use the promise-based hook:

```tsx
const confirm = useConfirm();
…
onSelect: async () => {
  if (await confirm({
    title: `Delete target “${t.name}”?`,
    description: "Scans already run against it keep their history.",
    confirmLabel: "Delete",
  })) del.mutate(t.id);
}
```

- **Title:** the question, naming the object. **Description:** the consequence, especially anything
  irreversible or user-visible ("Its token stops working immediately."). **`confirmLabel`:** the verb
  from the action that opened it.
- `tone` defaults to `danger`. Use `tone: "primary"` for consequential but non-destructive actions.

### Feedback and status

| Need | Component |
|---|---|
| Loading a section | `<Spinner />` (optional `label`) |
| A request or mutation failed | `<ErrorText error={…} />` (a danger `Alert`) |
| Outcome of an action ("Pushed 4 120 templates…") | `<Alert tone="success" onDismiss>` |
| A caveat about what's shown (partial results, untrusted coverage) | `<Alert tone="warning">` |
| Context banner ("Showing the linked target.") | `<Alert tone="info" action={…}>` |
| Status of a thing (scan state, enabled, healthy) | `<Badge tone>` / `StateBadge` / `FindingStateBadge` |
| Severity | `<SeverityBadge>` only |
| A secondary property (source, mode, discovery type) | `<Pill>` (outlined), or `<PropertyList>` for a row's set of properties |
| A list of values (tags, CWEs, endpoint pairs) | `<Tag>` / `<TagList>` |
| Nothing to show / no access | `<EmptyState>` (in place of a table: `TableEmpty`) |

The `Badge` tone scale is `neutral` · `info` · `success` · `warning` · `danger` · `accent`. A filled
**Badge** says what state something is in. An outlined **Pill** describes it. Don't mix them up.

### Pagination

`<OffsetPager offset total pageSize onChange />` for offset lists, or `<Pager summary hasPrev hasNext
onPrev onNext />` for cursor lists. Both show "Previous"/"Next" `sm` secondary buttons with the
position summary on the left ("31–60 of 412"). Inside a card, place the pager in a bordered footer
strip. Below a card, place it directly underneath.

### Tabs

`<Tabs tabs value onChange />` for switching between views of one resource (Templates: Catalog,
Custom templates, Sync). The caller renders the panel.

### Menus

Radix `DropdownMenu` with `menuContentClass` / `menuItemClass` / `menuSeparatorClass`. The trigger is a
`Button` (`asChild`) whose label ends in ▾ for a choice menu ("Export ▾"), or an `ActionMenu` "⋯" for
overflow actions.

### Saved views

A list with named filter presets offers them in one secondary `View: <name> ▾` dropdown. Each
item has a label and a one-line description, and the active preset is checked. When the current
filter matches no preset, the trigger reads "Custom filter". **Reset** is a `link` button placed after
the active-filter summary and shown **only** when the filter or sort differs from the default.
Don't put presets or reset in the toolbar as separate ghost buttons. Example: the findings list
(`FINDINGS_PRESETS` in `findingsFilters.ts`).

## Accessibility checklist

- Every interactive element shows the shared `focusRing` on keyboard focus. Primitives include it.
- Icon-only controls have a `label`/`aria-label`.
- Form controls sit inside a `Field` (a real `<label>`). Selects in toolbars without a visible label
  get an `aria-label`.
- Status changes after an action use `Alert` (it has `role="status"`/`role="alert"`).
- Sortable columns set `aria-sort`, and toggle buttons set `aria-expanded` or `aria-pressed`.
- Check both light and dark themes, and a ~400px-wide viewport.

## Adding to the system

1. Look for an existing primitive first. Most needs are a prop on one.
2. If something new is needed, add it to `ui.tsx` with a doc comment, and add a row or section here in
   the same PR.
3. Don't add page-local color, spacing or typography choices. If a page needs one, the system needs it.
