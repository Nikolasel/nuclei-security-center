import { useState } from "react";
import { Button } from "./ui";

/** Displays captured request/response evidence without inventing line breaks. */
export function CodeBlock({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard may be unavailable; ignore */
    }
  };
  return (
    <div className="relative">
      <Button
        variant="secondary"
        type="button"
        aria-label={copied ? "Copied code to clipboard" : "Copy code to clipboard"}
        onClick={copy}
        className="absolute right-2 top-2 px-2 py-1 text-xs"
      >
        {copied ? "Copied" : "Copy"}
      </Button>
      <pre className="max-h-96 overflow-auto whitespace-pre rounded-md bg-neutral-950 p-3 pr-16 text-xs leading-relaxed text-neutral-200">
        {text}
      </pre>
    </div>
  );
}
