import { useState } from "react";
import {
  type TemplateImportConflict,
  type TemplateImportResponse,
} from "../api";
import { Button, ErrorText, Field, Modal, Select } from "./ui";

export function TemplateArchiveImportModal({
  title,
  description,
  importArchive,
  onImported,
  onClose,
}: {
  title: string;
  description: string;
  importArchive: (file: File, conflict: TemplateImportConflict) => Promise<TemplateImportResponse>;
  onImported: (result: TemplateImportResponse) => void;
  onClose: () => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [conflict, setConflict] = useState<TemplateImportConflict>("skip");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>();

  const submit = async () => {
    if (!file) return;
    setPending(true);
    setError(undefined);
    try {
      onImported(await importArchive(file, conflict));
    } catch (cause) {
      setError(cause);
      setPending(false);
    }
  };

  return (
    <Modal open onOpenChange={(open) => !open && onClose()} title={title}>
      <div className="space-y-4">
        <p className="text-sm text-neutral-500">{description}</p>
        <Field label="Archive">
          <input
            type="file"
            accept=".tar.gz,.tgz,.json,application/gzip,application/json"
            className="block w-full text-xs text-neutral-500 file:mr-3 file:rounded-md file:border-0 file:bg-neutral-100 file:px-3 file:py-1.5 file:text-sm file:font-medium dark:file:bg-neutral-800"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
        </Field>
        <Field label="When an ID or set name already exists">
          <Select
            className="w-full"
            value={conflict}
            onChange={(event) => setConflict(event.target.value as TemplateImportConflict)}
          >
            <option value="skip">Skip existing items</option>
            <option value="overwrite">Overwrite existing custom items</option>
            <option value="rename">Import a renamed copy</option>
          </Select>
        </Field>
        <p className="text-xs text-neutral-500">
          Upstream YAML is reference material only and is never written by import. Set imports require referenced upstream IDs to already exist in this catalog.
        </p>
        {error !== undefined && <ErrorText error={error} />}
        <div className="flex justify-end gap-2">
          <Button disabled={pending} onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={pending || file == null} onClick={() => void submit()}>
            {pending ? "Validating and importing…" : "Import archive"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}
