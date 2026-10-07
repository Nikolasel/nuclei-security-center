import { describe, expect, it } from "vitest";
import {
  DEFAULT_TEMPLATE_REPO,
  channelFor,
  describeSourceSwitch,
  isDefaultRepo,
  sanitizeRepo,
} from "./syncSourceChannel";

describe("sanitizeRepo", () => {
  it("drops embedded credentials, query and fragment", () => {
    expect(
      sanitizeRepo("https://user:secret@github.com/org/repo.git?x=1#frag"),
    ).toBe("https://github.com/org/repo.git");
  });

  it("keeps a clean URL verbatim", () => {
    expect(sanitizeRepo(DEFAULT_TEMPLATE_REPO)).toBe(DEFAULT_TEMPLATE_REPO);
  });

  it("passes through input without a scheme", () => {
    expect(sanitizeRepo("  org/repo  ")).toBe("org/repo");
  });
});

describe("isDefaultRepo", () => {
  it("matches the default repository modulo credentials", () => {
    expect(isDefaultRepo(DEFAULT_TEMPLATE_REPO)).toBe(true);
    expect(
      isDefaultRepo("https://token@github.com/projectdiscovery/nuclei-templates.git"),
    ).toBe(true);
  });

  it("rejects other repositories, emptiness and non-URLs", () => {
    expect(isDefaultRepo("https://github.com/org/other.git")).toBe(false);
    expect(isDefaultRepo("")).toBe(false);
    expect(isDefaultRepo(undefined)).toBe(false);
    expect(isDefaultRepo("github.com/projectdiscovery/nuclei-templates.git")).toBe(false);
  });
});

describe("channelFor", () => {
  it("maps latest to stable on any repository", () => {
    expect(channelFor(DEFAULT_TEMPLATE_REPO, "latest")).toBe("stable");
    expect(channelFor("https://github.com/org/other.git", "latest")).toBe("stable");
  });

  it("maps main to preview only on the default repository", () => {
    expect(channelFor(DEFAULT_TEMPLATE_REPO, "main")).toBe("preview");
    expect(channelFor("https://github.com/org/other.git", "main")).toBe("custom");
    // No repo known (legacy rows): main cannot be confirmed as preview.
    expect(channelFor(undefined, "main")).toBe("custom");
  });

  it("maps anything else to custom", () => {
    expect(channelFor(DEFAULT_TEMPLATE_REPO, "v10.5.0")).toBe("custom");
    expect(channelFor(DEFAULT_TEMPLATE_REPO, "refs/tags/v10.5.0")).toBe("custom");
  });
});

describe("describeSourceSwitch", () => {
  it("labels a channel change", () => {
    expect(
      describeSourceSwitch(
        { repo: DEFAULT_TEMPLATE_REPO, ref: "latest" },
        { repo: DEFAULT_TEMPLATE_REPO, ref: "main" },
      ),
    ).toBe("Stable → Preview");
  });

  it("labels a repository change within one channel", () => {
    expect(
      describeSourceSwitch(
        { repo: "https://github.com/org/one.git", ref: "main" },
        { repo: "https://github.com/org/two.git", ref: "main" },
      ),
    ).toBe("repository changed");
  });

  it("ignores credential-only differences and identical sources", () => {
    expect(
      describeSourceSwitch(
        { repo: "https://user:a@github.com/org/repo.git", ref: "main" },
        { repo: "https://github.com/org/repo.git", ref: "main" },
      ),
    ).toBe("");
    expect(
      describeSourceSwitch(
        { repo: DEFAULT_TEMPLATE_REPO, ref: "latest" },
        { repo: DEFAULT_TEMPLATE_REPO, ref: "latest" },
      ),
    ).toBe("");
  });

  it("returns empty when either run predates the recorded source", () => {
    expect(
      describeSourceSwitch({ repo: DEFAULT_TEMPLATE_REPO }, { repo: DEFAULT_TEMPLATE_REPO, ref: "main" }),
    ).toBe("");
    expect(
      describeSourceSwitch({ repo: DEFAULT_TEMPLATE_REPO, ref: "latest" }, {}),
    ).toBe("");
  });

  it("labels a channel change even when the older run has no recorded repo", () => {
    expect(
      describeSourceSwitch({ ref: "latest" }, { repo: DEFAULT_TEMPLATE_REPO, ref: "main" }),
    ).toBe("Stable → Preview");
  });

  it("does not claim a repository change from a missing repo", () => {
    expect(
      describeSourceSwitch({ ref: "main" }, { repo: "https://github.com/org/two.git", ref: "main" }),
    ).toBe("");
  });
});