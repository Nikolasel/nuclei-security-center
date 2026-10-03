import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { importScanBundle, type ImportCoverageMode } from "../api";
import { Button, Checkbox, ErrorText, Field, FileInput, FormHint, Modal, ModalActions, Select } from "../components/ui";

export function ImportBundleModal({ onClose }: { onClose: () => void }) {
  const navigate = useNavigate();
  const qc = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [fileName, setFileName] = useState("");
  const [conflict, setConflict] = useState<"error" | "duplicate">("error");
  const [coverage, setCoverage] = useState<ImportCoverageMode>("ignore");

  const importBundle = useMutation({
    mutationFn: () => {
      const file = inputRef.current?.files?.[0];
      if (!file) throw new Error("choose a bundle file first");
      return importScanBundle(file, conflict, coverage);
    },
    onSuccess: (res) => {
      void qc.invalidateQueries({ queryKey: ["scans"] });
      navigate(`/scans/${res.scan_id}`);
    },
  });

  return (
    <Modal
      open
      onOpenChange={(v) => !v && onClose()}
      title="Import scan bundle"
      description="Recreate a scan and its results from an exported bundle. This instance re-derives its own finding lifecycle from the results."
    >
      <div className="space-y-4">
        <FormHint>
          Accepts <span className="font-mono">.nsc-bundle.json</span> or{" "}
          <span className="font-mono">.nsc-bundle.zip</span> (#136). References to targets, template sets or scan
          policies that do not exist here fall back to their defaults.
        </FormHint>
        <Field label="Bundle file">
          <FileInput
            ref={inputRef}
            accept=".json,.zip,application/json,application/zip"
            onChange={(e) => setFileName(e.target.files?.[0]?.name ?? "")}
          />
        </Field>
        <Field label="If a scan with the exported id already exists">
          <Select
            value={conflict}
            onChange={(e) => setConflict(e.target.value as "error" | "duplicate")}
            className="w-full"
          >
            <option value="error">Refuse to import (recommended)</option>
            <option value="duplicate">Import under a new id</option>
          </Select>
        </Field>
        <Checkbox
          label="Use imported coverage to evaluate mitigations"
          description="Imported endpoint coverage is ignored by default. Opt in only when the exporting scan is trusted."
          checked={coverage === "trust"}
          onChange={(checked) => setCoverage(checked ? "trust" : "ignore")}
        />
        {coverage === "trust" && (
          <FormHint tone="warning">
            Only enable this when you trust the exporting scanner and its scope. A coverage-only bundle may mark
            existing findings as mitigated.
          </FormHint>
        )}
        {importBundle.isError && <ErrorText error={importBundle.error} />}
        <ModalActions>
          <Button onClick={onClose}>Cancel</Button>
          <Button variant="primary" disabled={importBundle.isPending || !fileName} onClick={() => importBundle.mutate()}>
            {importBundle.isPending ? "Importing…" : "Import bundle"}
          </Button>
        </ModalActions>
      </div>
    </Modal>
  );
}
