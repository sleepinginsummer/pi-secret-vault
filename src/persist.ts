import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { SecretStore, type StoredSource } from "./store.ts";
import { MIN_SCRUBABLE_LENGTH } from "./refs.ts";
import { isEnabled } from "./state.ts";
import { validateRemark } from "./remark.ts";
import type { SecretSource, Vault } from "./vault.ts";

let store: SecretStore | undefined;
export function getStore(): SecretStore {
  store ??= new SecretStore(join(getAgentDir(), "pi-secret-vault"));
  return store;
}
export function setStoreForTests(next: SecretStore | undefined): void {
  store = next;
  seen = new WeakMap();
}

let seen = new WeakMap<Vault, string>();

/**
 * Bring a session's in-memory vault up to date with the file.
 *
 * Stored values enter as tier `ambient`, session ones stay `session`; a session value keeps its
 * name if the two clash. Off means off: `/sec off` is not undone by the next hook.
 * Returns an error message rather than throwing: an unreadable vault must not stop the session.
 */
export function syncVault(vault: Vault, target: SecretStore = getStore()): string | undefined {
  if (!isEnabled()) return undefined;
  try {
    const signature = target.signature();
    if (seen.get(vault) === signature) return undefined;
    const { values, failed } = target.loadAll();
    const present = new Set(values.map((v) => v.name));
    for (const entry of vault.entries()) {
      if (entry.tier === "ambient" && !present.has(entry.name)) vault.remove(entry.name);
    }
    for (const { name, value, source, remark } of values) {
      const current = vault.get(name);
      if (current && current.tier === "session") continue;
      if (current?.value === value) {
        // Without this a remark edited elsewhere would never reach a running session.
        if (current.remark !== remark) vault.setRemark(name, remark);
        continue;
      }
      vault.add(name, value, source === "web" ? "prompt" : source, "ambient");
      vault.setRemark(name, remark);
    }
    seen.set(vault, signature);
    return failed.length ? `pi-secret: could not decrypt ${failed.join(", ")}` : undefined;
  } catch (error) {
    return `pi-secret: stored secrets are unavailable — ${error instanceof Error ? error.message : String(error)}`;
  }
}

/**
 * Store a value the user deliberately gave. On failure it still works for this session, and the
 * returned text says so: losing the persistence must not lose the value they just typed.
 */
export function saveSecret(vault: Vault, name: string, value: string, source: SecretSource, target: SecretStore = getStore(), remark?: string): { persisted: boolean; note: string } {
  const short = value.length < MIN_SCRUBABLE_LENGTH
    ? ` · shorter than ${MIN_SCRUBABLE_LENGTH} characters, so it will NOT be hidden in output`
    : "";
  try {
    target.put(name, value, source as StoredSource, remark);
    vault.add(name, value, source, "ambient", remark);
    seen.delete(vault);
    return { persisted: true, note: `saved encrypted, available in every session${short}` };
  } catch (error) {
    vault.add(name, value, source, "session", remark);
    return { persisted: false, note: `this session only (${error instanceof Error ? error.message : String(error)})${short}` };
  }
}

export function forgetStored(name: string, target: SecretStore = getStore()): void {
  target.remove(name);
}
export function renameStored(from: string, to: string, target: SecretStore = getStore()): void {
  target.rename(from, to);
}

export type RemarkOutcome =
  | { ok: true; remark: string | undefined; previous: string | undefined; persisted: boolean }
  | { ok: false; reason: string };

/**
 * The one write path for a remark, shared by `sec_remark` and `/sec remark`. A saved secret is
 * written to the file first, so a storage failure leaves memory and disk agreeing.
 */
export function applyRemark(vault: Vault, name: string, raw: string, target: SecretStore = getStore()): RemarkOutcome {
  const entry = vault.get(name);
  if (!entry) return { ok: false, reason: `sec:${name} not found` };
  const checked = validateRemark(raw, vault);
  if (!checked.ok) return checked;
  const persisted = entry.tier === "ambient";
  if (persisted) {
    try {
      if (!target.setRemark(name, checked.remark)) return { ok: false, reason: `sec:${name} is no longer in the vault file` };
    } catch (error) {
      return { ok: false, reason: `could not save the remark: ${error instanceof Error ? error.message : String(error)}` };
    }
    seen.delete(vault);
  }
  vault.setRemark(name, checked.remark);
  return { ok: true, remark: checked.remark, previous: entry.remark, persisted };
}
