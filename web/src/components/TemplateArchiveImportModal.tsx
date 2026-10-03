import { useState } from "react";
import {
  type TemplateImportConflict,
  type TemplateImportResponse,
} from "../api";
import { Button, ErrorText, Field, FileInput, Modal, ModalActions, Select } from "./ui";

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
    <Modal open onOpenChange={(open) => !open && onClose()} title={title} description={description}>
      <div className="space-y-4">
        <Field label="Archive" required>
          <FileInput
            accept=".tar.gz,.tgz,.json,application/gzip,application/json"
            onChange={(event) => setFile(event.target.files?.[0] ?? null)}
          />
        </Field>
        <Field
          label="When an ID or set name already exists"
          hint="Upstream YAML is reference material only and is never written by import. Set imports require referenced upstream IDs to already exist in this catalog."
        >
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
        {error !== undefined && <ErrorText error={error} />}
        <ModalActions>
          <Button disabled={pending} onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={pending || file == null} onClick={() => void submit()}>
            {pending ? "Validating and importing…" : "Import archive"}
          </Button>
        </ModalActions>
      </div>
    </Modal>
  );
}
