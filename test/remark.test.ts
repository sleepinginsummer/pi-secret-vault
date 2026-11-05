import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { injectToolCall } from "../src/glue.ts";
import { applyRemark, saveSecret, setStoreForTests, syncVault } from "../src/persist.ts";
import { PI_SECRET_PROMPT } from "../src/prompt.ts";
import { MAX_REMARK_CHARS, REMARK_GUIDE, validateRemark } from "../src/remark.ts";
import { scrubText } from "../src/scrub.ts";
import { fileKeyProvider, SecretStore } from "../src/store.ts";
import { createSecListTool } from "../src/tools/sec-list.ts";
import { createSecRemarkTool } from "../src/tools/sec-remark.ts";
import { createSecRequestTool } from "../src/tools/sec-request.ts";
import { Vault } from "../src/vault.ts";

const VALUE = "plain-value-123456";
// Built at runtime so this file does not itself contain credential-shaped literals.
const fakeToken = `ghp_${"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6"}`;

let dir: string;
let store: SecretStore;
let vault: Vault;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pi-secret-remark-"));
  store = new SecretStore(dir, fileKeyProvider(dir));
  setStoreForTests(store);
  vault = new Vault("a");
});
afterEach(() => {
  setStoreForTests(undefined);
  rmSync(dir, { recursive: true, force: true });
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const run = (tool: any, params: unknown, ctx: unknown = { hasUI: false }) => tool.execute("id", params, undefined, undefined, ctx);

describe("validateRemark", () => {
  it.each([
    "company Jenkins deploys · https://jenkins.example.com · username deploy",
    "开发环境 RabbitMQ 管理台 · http://10.0.0.8:15672 · 用户名 admin",
    "develop-rabbit-mq-management-console for the staging cluster",
    "token for the GitHub CLI, user sleepinginsummer",
    "host prod-eu-west-1-rabbitmq-cluster-03.internal.example.com",
  ])("accepts %s", (remark) => {
    expect(validateRemark(remark, vault)).toEqual({ ok: true, remark });
  });

  it("flattens to one line, and treats empty as clearing", () => {
    expect(validateRemark(" a\n  b\tc ", vault)).toEqual({ ok: true, remark: "a b c" });
    expect(validateRemark("  \n ", vault)).toEqual({ ok: true, remark: undefined });
  });

  it.each([
    ["a ref", "use {{sec:gh}}"],
    ["a provider token", `github ${fakeToken}`],
    ["an unprefixed random token", `key ${"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6"}`],
    ["a URL password", "https://deploy:hunter2hunter2@ci.example.com"],
    ["a credential query", "https://ci.example.com/?token=abc"],
    ["an over-long remark", "x ".repeat(MAX_REMARK_CHARS)],
  ])("refuses %s without quoting it", (_label, remark) => {
    const out = validateRemark(remark, vault);
    expect(out.ok).toBe(false);
    if (!out.ok) expect(out.reason).not.toContain(fakeToken);
  });

  it("refuses a value already in the vault", () => {
    vault.add("gh", VALUE, "prompt");
    expect(validateRemark(`password is ${VALUE}`, vault).ok).toBe(false);
  });

  it("keeps the guide and system prompt examples clear of the scrubber", () => {
    expect(scrubText(REMARK_GUIDE, vault, { shapes: true }).hits).toBe(0);
    expect(scrubText(PI_SECRET_PROMPT, vault, { shapes: true }).hits).toBe(0);
  });
});

describe("remark storage", () => {
  it("survives replacing the value, renaming, and needs no key to change", () => {
    store.put("gh", VALUE, "prompt", "first");
    store.put("gh", `${VALUE}-2`, "web");
    expect(store.list()[0]).toMatchObject({ remark: "first" });
    store.rename("gh", "github");
    expect(store.list()[0]).toMatchObject({ name: "github", remark: "first" });
    expect(store.loadAll().values[0]).toMatchObject({ value: `${VALUE}-2`, remark: "first" });
    const noKey = new SecretStore(dir, { read: () => { throw new Error("no key access"); }, create: () => { throw new Error("no key access"); } });
    expect(noKey.setRemark("github", "second")).toBe(true);
    expect(noKey.setRemark("missing", "x")).toBe(false);
    expect(noKey.list()[0]).toMatchObject({ remark: "second" });
    noKey.setRemark("github", undefined);
    expect(JSON.parse(readFileSync(join(dir, "vault.json"), "utf8")).records.github).not.toHaveProperty("remark");
  });

  it("reaches a running session whose value did not change", () => {
    store.put("gh", VALUE, "prompt");
    syncVault(vault);
    expect(vault.get("gh")?.remark).toBeUndefined();
    store.setRemark("gh", "added elsewhere");
    syncVault(vault);
    expect(vault.get("gh")?.remark).toBe("added elsewhere");
    store.setRemark("gh", undefined);
    syncVault(vault);
    expect(vault.get("gh")?.remark).toBeUndefined();
  });

  it("writes a saved secret to disk and a session one to memory only", () => {
    saveSecret(vault, "saved", VALUE, "prompt");
    vault.add("session", `${VALUE}-s`, "paste");
    expect(applyRemark(vault, "saved", "for ci")).toMatchObject({ ok: true, persisted: true });
    expect(applyRemark(vault, "session", "for now")).toMatchObject({ ok: true, persisted: false });
    expect(store.list().map((e) => [e.name, e.remark])).toEqual([["saved", "for ci"]]);
    expect(vault.get("session")?.remark).toBe("for now");
    expect(applyRemark(vault, "missing", "x").ok).toBe(false);
  });

  it("promoting a session secret keeps its remark, and a rename in memory carries it", () => {
    vault.add("session", VALUE, "paste", "session", "for now");
    vault.remove("session");
    saveSecret(vault, "session", VALUE, "paste", undefined, "for now");
    expect(store.list()[0]).toMatchObject({ remark: "for now" });
    vault.rename("session", "kept");
    expect(vault.get("kept")?.remark).toBe("for now");
    expect(vault.entries()[0]).not.toHaveProperty("value");
  });
});

describe("tools", () => {
  it("sec_list shows the remark and never a value", async () => {
    saveSecret(vault, "gh", VALUE, "prompt", undefined, "GitHub CLI · user deploy");
    vault.add("plain", `${VALUE}-2`, "paste");
    const out = await run(createSecListTool(() => vault), {});
    const text = out.content[0].text;
    expect(text).toContain("sec:gh · len 18 · ambient-only · remark: GitHub CLI · user deploy");
    expect(text).toMatch(/sec:plain · len 20 · session-only$/m);
    expect(JSON.stringify(out)).not.toContain(VALUE);
  });

  it("sec_remark changes it, tells the user old and new, and refuses a credential", async () => {
    saveSecret(vault, "gh", VALUE, "prompt", undefined, "old");
    const notices: string[] = [];
    const ctx = { hasUI: true, ui: { notify: (m: string) => notices.push(m) } };
    const tool = createSecRemarkTool(() => vault);
    const ok = await run(tool, { name: "sec:gh", remark: "new" }, ctx);
    expect(ok.details).toEqual({ name: "gh", ok: true });
    expect(store.list()[0]).toMatchObject({ remark: "new" });
    expect(notices[0]).toContain("was: old");
    expect(notices[0]).toContain("now: new");
    const bad = await run(tool, { name: "gh", remark: `key ${fakeToken}` }, ctx);
    expect(bad.details.ok).toBe(false);
    expect(JSON.stringify(bad)).not.toContain(fakeToken);
    expect(store.list()[0]).toMatchObject({ remark: "new" });
  });

  it("sec_request saves its remark, and refuses a bad one before prompting", async () => {
    let prompts = 0;
    const ctx = { hasUI: true, mode: "rpc", ui: { input: async () => { prompts++; return VALUE; }, notify() {} } };
    const tool = createSecRequestTool(() => vault);
    const bad = await run(tool, { name: "ci", remark: `x ${fakeToken}` }, ctx);
    expect(bad.details.error).toBe("invalid-remark");
    expect(prompts).toBe(0);
    await run(tool, { name: "ci", remark: "Jenkins · user deploy" }, ctx);
    expect(prompts).toBe(1);
    expect(store.list()[0]).toMatchObject({ name: "ci", remark: "Jenkins · user deploy" });
  });

  it.each(["sec_remark", "sec_request"])("%s arguments are never expanded", (tool) => {
    vault.add("gh", VALUE, "prompt");
    const input = { name: "gh", remark: "see {{sec:gh}}" };
    const out = injectToolCall(tool, input, vault);
    expect(out.blocked?.reason).toContain("not valid");
    expect(input.remark).toBe("see {{sec:gh}}");
  });
});
