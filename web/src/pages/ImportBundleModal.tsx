import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { importScanBundle } from "../api";
import { Button, ErrorText, Field, Modal } from "../components/ui";

export function ImportBundleModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState("");
  const [conflict, setConflict] = useState<"error" | "duplicate">("error");

  const importBundle = useMutation({
    mutationFn: () => {
      const file = inputRef.current?.files?.[0];
      if (!file) throw new Error("choose a bundle file first");
      return importScanBundle(file, conflict);
    },
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["scans"] });
      navigate(`/scans/${res.scan_id}`);
    },
  });

  const selectCls =
    "w-full rounded-md border border-neutral-300 bg-white px-3 py-1.5 text-sm dark:border-neutral-700 dark:bg-neutral-800";

  return (
    <Modal open onOpenChange={(v) => !v && onClose()} title="Import scan bundle">
      <div className="space-y-4">
        <p className="text-sm text-neutral-500">
          Recreate a scan and its findings lifecycle from an exported{" "}
          <span className="font-mono">.nsc-bundle.json</span> or{" "}
          <span className="font-mono">.nsc-bundle.zip</span> file (#136).
          References to targets, template sets or scan policies that do not exist
          here fall back to their defaults.
        </p>
        <Field label="Bundle file">
          <input
            ref={inputRef}
            type="file"
            accept=".json,.zip,application/json,application/zip"
            className={selectCls}
            onChange={(e) => setFileName(e.target.files?.[0]?.name ?? "")}
          />
        </Field>
        <Field label="If a scan with the exported id already exists">
          <select value={conflict} onChange={(e) => setConflict(e.target.value as "error" | "duplicate")} className={selectCls}>
            <option value="error">Refuse to import (recommended)</option>
            <option value="duplicate">Import under a new id</option>
          </select>
        </Field>
        {fileName && <p className="text-xs text-neutral-400">Selected: {fileName}</p>}
        {importBundle.isError && <ErrorText error={importBundle.error} />}
        <div className="flex justify-end gap-2">
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={importBundle.isPending} onClick={() => importBundle.mutate()}>
            {importBundle.isPending ? "Importing…" : "Import bundle"}
          </Button>
        </div>
      </div>
    </Modal>
  );
}