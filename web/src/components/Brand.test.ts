import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Brand } from "./Brand";

function render(compact: boolean) {
  return renderToStaticMarkup(createElement(MemoryRouter, null, createElement(Brand, { compact })));
}

describe("Brand", () => {
  it("shows the Goodnight Check lockup for dark backgrounds in the header", () => {
    const html = render(false);
    expect(html).toContain('src="/goodnight-check-lockup-on-dark.svg"');
    expect(html).toContain('aria-label="Goodnight Check home"');
    expect(html).not.toContain("goodnightsec-mark.svg");
    // The two-line lockup ("GOODNIGHT" over "Check") is gone.
    expect(html).not.toContain("uppercase");
    expect(html).not.toMatch(/>\s*(Goodnight|Check)\s*</);
  });

  it("shows the mark alone when compact", () => {
    const html = render(true);
    expect(html).toContain('src="/goodnightsec-mark.svg"');
    expect(html).not.toContain("lockup");
  });

  it("ships the outlined lockup file from the corporate design", () => {
    const svg = readFileSync(new URL("../../public/goodnight-check-lockup-on-dark.svg", import.meta.url), "utf8");
    expect(svg).toContain('aria-label="Goodnight Check"');
    expect(svg).not.toContain("<text");
  });
});
