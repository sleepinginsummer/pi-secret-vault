import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { fileKeyProvider, SecretStore } from "../src/store.ts";
import { saveSecret, setStoreForTests, syncVault } from "../src/persist.ts";
import { Vault } from "../src/vault.ts";

let dir: string;
let store: SecretStore;
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "pi-secret-vault-"));
  store = new SecretStore(dir, fileKeyProvider(dir));
  setStoreForTests(store);
});
afterEach(() => {
  setStoreForTests(undefined);
  rmSync(dir, { recursive: true, force: true });
});

describe("SecretStore", () => {
  it("round-trips across instances and never writes plaintext", () => {
    store.put("gh", "plain-value-123", "prompt");
    const raw = readFileSync(join(dir, "vault.json"), "utf8");
    expect(raw).not.toContain("plain-value-123");
    expect(statSync(join(dir, "vault.json")).mode & 0o777).toBe(0o600);
    const again = new SecretStore(dir, fileKeyProvider(dir));
    expect(again.loadAll().values.map((v) => [v.name, v.value])).toEqual([["gh", "plain-value-123"]]);
    expect(again.list()[0]).toMatchObject({ name: "gh", length: 15, source: "prompt" });
  });

  it("binds a record to its name", () => {
    store.put("a", "value-for-a", "prompt");
    const file = JSON.parse(readFileSync(join(dir, "vault.json"), "utf8"));
    file.records.b = file.records.a;
    delete file.records.a;
    writeFileSync(join(dir, "vault.json"), JSON.stringify(file));
    expect(store.loadAll()).toEqual({ values: [], failed: ["b"] });
  });

  it("renames by re-encrypting, and removes", () => {
    store.put("a", "value-for-a", "prompt");
    expect(store.rename("a", "b")).toBe(true);
    expect(store.loadAll().values[0]).toMatchObject({ name: "b", value: "value-for-a" });
    expect(store.remove("b")).toBe(true);
    expect(store.list()).toEqual([]);
  });

  it("will not mint a new key over existing records", () => {
    store.put("a", "value-for-a", "prompt");
    rmSync(join(dir, "vault.key"));
    const orphan = new SecretStore(dir, fileKeyProvider(dir));
    expect(() => orphan.put("b", "value-for-b", "prompt")).toThrow(/key is gone/);
    expect(() => orphan.loadAll()).toThrow(/key is gone/);
  });
});

describe("session sync", () => {
  it("loads stored values, follows deletion, and keeps session values", () => {
    store.put("saved", "stored-value-1", "prompt");
    const vault = new Vault("s1");
    vault.add("mine", "session-value-1", "paste");
    expect(syncVault(vault, store)).toBeUndefined();
    expect(vault.resolve("saved")).toBe("stored-value-1");
    store.remove("saved");
    syncVault(vault, store);
    expect(vault.has("saved")).toBe(false);
    expect(vault.resolve("mine")).toBe("session-value-1");
  });

  it("a session in another vault picks up what was saved elsewhere", () => {
    const a = new Vault("a");
    const b = new Vault("b");
    syncVault(b, store);
    saveSecret(a, "shared", "shared-value-1", "prompt", store);
    syncVault(b, store);
    expect(b.resolve("shared")).toBe("shared-value-1");
  });

  it("a storage failure keeps the value for this session and says so", () => {
    const broken = { put() { throw new Error("no keychain"); } } as unknown as SecretStore;
    const vault = new Vault("s");
    const out = saveSecret(vault, "x", "value-kept-1", "prompt", broken);
    expect(out.persisted).toBe(false);
    expect(out.note).toContain("this session only");
    expect(vault.resolve("x")).toBe("value-kept-1");
  });

  it("warns about a value too short to hide", () => {
    expect(saveSecret(new Vault("s"), "x", "abc", "prompt", store).note).toContain("NOT be hidden");
  });
});
