/** Lists Nuclei extracted values, which can be long unbroken tokens (e.g. NTLM
 * blobs), so each value wraps at any character and very tall ones scroll. */
export function ExtractedResults({ items }: { items: string[] }) {
  return (
    <ul className="space-y-1.5">
      {items.map((item, index) => (
        <li
          key={`${item}-${index}`}
          className="max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-neutral-100 px-2 py-1 font-mono text-xs dark:bg-neutral-800"
        >
          {item}
        </li>
      ))}
    </ul>
  );
}
