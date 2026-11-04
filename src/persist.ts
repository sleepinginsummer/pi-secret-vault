import { join } from "node:path";
import { getAgentDir } from "@earendil-works/pi-coding-agent";
import { SecretStore, type StoredSource } from "./store.ts";
import { MIN_SCRUBABLE_LENGTH } from "./refs.ts";
import { isEnabled } from "./state.ts";
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
    for (const { name, value, source } of values) {
      const current = vault.get(name);
      if (current && current.tier === "session") continue;
      if (current?.value === value) continue;
      vault.add(name, value, source === "web" ? "prompt" : source, "ambient");
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
export function saveSecret(vault: Vault, name: string, value: string, source: SecretSource, target: SecretStore = getStore()): { persisted: boolean; note: string } {
  const short = value.length < MIN_SCRUBABLE_LENGTH
    ? ` · shorter than ${MIN_SCRUBABLE_LENGTH} characters, so it will NOT be hidden in output`
    : "";
  try {
    target.put(name, value, source as StoredSource);
    vault.add(name, value, source, "ambient");
    seen.delete(vault);
    return { persisted: true, note: `saved encrypted, available in every session${short}` };
  } catch (error) {
    vault.add(name, value, source);
    return { persisted: false, note: `this session only (${error instanceof Error ? error.message : String(error)})${short}` };
  }
}

export function forgetStored(name: string, target: SecretStore = getStore()): void {
  target.remove(name);
}
export function renameStored(from: string, to: string, target: SecretStore = getStore()): void {
  target.rename(from, to);
}
