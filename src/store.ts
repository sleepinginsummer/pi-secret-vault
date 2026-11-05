import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, rmdirSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";

/**
 * The encrypted vault on disk. pi-web's `lib/secret-vault.ts` reads and writes the same file, so
 * the layout below is a contract: bump `version` rather than changing a field's meaning.
 *
 *   <agentDir>/pi-secret-vault/vault.json   { version: 1, records: { name: Record } }
 *   AES-256-GCM per record, AAD `pi-secret-vault:v1:<name>`: a record copied onto another name
 *   fails to decrypt. Names and metadata are plaintext, because listing must not need the key.
 *   `remark` is optional plaintext metadata, added without a version bump because a reader that
 *   does not know it loses nothing: bumping would make older readers refuse the whole vault.
 *
 * The master key lives in the macOS Keychain (service `pi-secret-vault`, account = first 16 hex
 * of sha256(vault dir), so dev and production never share one). Elsewhere it is a 0600 key file
 * beside the vault, which only protects against reading the vault file alone.
 */
export const VAULT_VERSION = 1;
const KEYCHAIN_SERVICE = "pi-secret-vault";
const LOCK_WAIT_MS = 3000;
const LOCK_STALE_MS = 15000;

export type StoredSource = "prompt" | "file" | "paste" | "output" | "web";

export interface StoredRecord {
  iv: string;
  tag: string;
  ct: string;
  addedAt: number;
  source: StoredSource;
  length: number;
  remark?: string;
}

interface VaultFile {
  version: number;
  records: Record<string, StoredRecord>;
}

export interface KeyProvider {
  /** The key if one exists, undefined if none was ever created. Throws when it cannot tell. */
  read(): Buffer | undefined;
  create(): Buffer;
}

export function keychainAccount(dir: string): string {
  return createHash("sha256").update(dir, "utf8").digest("hex").slice(0, 16);
}

export function keychainKeyProvider(dir: string): KeyProvider {
  const account = keychainAccount(dir);
  return {
    read() {
      try {
        const out = execFileSync("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 15000,
        });
        return Buffer.from(out.trim(), "base64");
      } catch (error) {
        // 44 is errSecItemNotFound. Anything else (locked keychain, denied) must NOT look like
        // "no key yet", or the caller would mint a new key and strand every stored record.
        if ((error as { status?: number }).status === 44) return undefined;
        throw new Error("the macOS Keychain refused to hand over the vault key");
      }
    },
    create() {
      const key = randomBytes(32);
      // Through stdin, not argv: argv is visible to every process in `ps`.
      execFileSync("security", ["-i"], {
        input: `add-generic-password -U -s ${KEYCHAIN_SERVICE} -a ${account} -l ${KEYCHAIN_SERVICE} -w ${key.toString("base64")}\n`,
        stdio: ["pipe", "ignore", "ignore"],
        timeout: 15000,
      });
      return key;
    },
  };
}

export function fileKeyProvider(dir: string): KeyProvider {
  const path = join(dir, "vault.key");
  return {
    read: () => (existsSync(path) ? Buffer.from(readFileSync(path, "utf8").trim(), "base64") : undefined),
    create() {
      const key = randomBytes(32);
      writeFileSync(path, key.toString("base64"), { mode: 0o600, flag: "wx" });
      return key;
    },
  };
}

export function defaultKeyProvider(dir: string): KeyProvider {
  return process.platform === "darwin" ? keychainKeyProvider(dir) : fileKeyProvider(dir);
}

function aad(name: string): Buffer {
  return Buffer.from(`pi-secret-vault:v${VAULT_VERSION}:${name}`, "utf8");
}

export class SecretStore {
  readonly #dir: string;
  readonly #path: string;
  readonly #keys: KeyProvider;
  #key: Buffer | undefined;

  constructor(dir: string, keys: KeyProvider = defaultKeyProvider(dir)) {
    this.#dir = dir;
    this.#path = join(dir, "vault.json");
    this.#keys = keys;
  }

  /** Cheap change detection, so every hook can sync without decrypting. */
  signature(): string {
    const st = statSync(this.#path, { throwIfNoEntry: false });
    return st ? `${st.ino}:${st.size}:${st.mtimeMs}` : "absent";
  }

  list(): Array<{ name: string } & Omit<StoredRecord, "iv" | "tag" | "ct">> {
    return Object.entries(this.#read().records).map(([name, r]) => ({ name, addedAt: r.addedAt, source: r.source, length: r.length, ...(r.remark ? { remark: r.remark } : {}) }));
  }

  /** Every value that decrypts, plus the names that did not. One bad record costs only itself. */
  loadAll(): { values: Array<{ name: string; value: string; source: StoredSource; addedAt: number; remark?: string }>; failed: string[] } {
    const file = this.#read();
    const names = Object.keys(file.records);
    if (!names.length) return { values: [], failed: [] };
    const key = this.#existingKey();
    const values: Array<{ name: string; value: string; source: StoredSource; addedAt: number; remark?: string }> = [];
    const failed: string[] = [];
    for (const name of names) {
      const r = file.records[name]!;
      try {
        const d = createDecipheriv("aes-256-gcm", key, Buffer.from(r.iv, "base64"));
        d.setAAD(aad(name));
        d.setAuthTag(Buffer.from(r.tag, "base64"));
        const value = Buffer.concat([d.update(Buffer.from(r.ct, "base64")), d.final()]).toString("utf8");
        values.push({ name, value, source: r.source, addedAt: r.addedAt, ...(r.remark ? { remark: r.remark } : {}) });
      } catch {
        failed.push(name);
      }
    }
    return { values, failed };
  }

  /** An undefined remark keeps the record's existing one: replacing a value is not forgetting what it is for. */
  put(name: string, value: string, source: StoredSource, remark?: string): void {
    this.#locked(() => {
      const file = this.#read();
      const key = this.#writeKey(file);
      file.records[name] = this.#seal(key, name, value, source, Date.now(), remark ?? file.records[name]?.remark);
      this.#write(file);
    });
  }

  remove(name: string): boolean {
    return this.#locked(() => {
      const file = this.#read();
      if (!file.records[name]) return false;
      delete file.records[name];
      this.#write(file);
      return true;
    });
  }

  /** Re-encrypts, because the name is bound into the ciphertext. */
  rename(from: string, to: string): boolean {
    return this.#locked(() => {
      const file = this.#read();
      const old = file.records[from];
      if (!old || file.records[to]) return false;
      const key = this.#existingKey();
      const d = createDecipheriv("aes-256-gcm", key, Buffer.from(old.iv, "base64"));
      d.setAAD(aad(from));
      d.setAuthTag(Buffer.from(old.tag, "base64"));
      const value = Buffer.concat([d.update(Buffer.from(old.ct, "base64")), d.final()]).toString("utf8");
      file.records[to] = this.#seal(key, to, value, old.source, old.addedAt, old.remark);
      delete file.records[from];
      this.#write(file);
      return true;
    });
  }

  /** Metadata only, so it needs no key. An undefined remark clears it. */
  setRemark(name: string, remark: string | undefined): boolean {
    return this.#locked(() => {
      const file = this.#read();
      const record = file.records[name];
      if (!record) return false;
      if (remark) record.remark = remark;
      else delete record.remark;
      this.#write(file);
      return true;
    });
  }

  #seal(key: Buffer, name: string, value: string, source: StoredSource, addedAt: number, remark?: string): StoredRecord {
    const iv = randomBytes(12);
    const c = createCipheriv("aes-256-gcm", key, iv);
    c.setAAD(aad(name));
    const ct = Buffer.concat([c.update(value, "utf8"), c.final()]);
    return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ct: ct.toString("base64"), addedAt, source, length: value.length, ...(remark ? { remark } : {}) };
  }

  #read(): VaultFile {
    if (!existsSync(this.#path)) return { version: VAULT_VERSION, records: {} };
    const file = JSON.parse(readFileSync(this.#path, "utf8")) as VaultFile;
    if (file.version !== VAULT_VERSION) throw new Error(`vault file has unsupported version ${file.version}`);
    return file;
  }

  #write(file: VaultFile): void {
    const tmp = `${this.#path}.${process.pid}.tmp`;
    writeFileSync(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
    renameSync(tmp, this.#path);
  }

  #existingKey(): Buffer {
    this.#key ??= this.#keys.read();
    if (!this.#key) throw new Error("the vault has records but its key is gone, so they cannot be read");
    return this.#key;
  }

  /** A new key only for a vault with nothing to strand. */
  #writeKey(file: VaultFile): Buffer {
    this.#key ??= this.#keys.read();
    if (this.#key) return this.#key;
    if (Object.keys(file.records).length) throw new Error("the vault has records but its key is gone, so they cannot be read");
    this.#key = this.#keys.create();
    return this.#key;
  }

  #locked<T>(fn: () => T): T {
    mkdirSync(this.#dir, { recursive: true, mode: 0o700 });
    chmodSync(this.#dir, 0o700);
    const lock = join(this.#dir, "vault.lock");
    const deadline = Date.now() + LOCK_WAIT_MS;
    for (;;) {
      try {
        mkdirSync(lock);
        break;
      } catch {
        const st = statSync(lock, { throwIfNoEntry: false });
        if (st && Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          try { rmdirSync(lock); } catch { /* another process cleared it */ }
          continue;
        }
        if (Date.now() > deadline) throw new Error("timed out waiting for the vault lock");
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 25);
      }
    }
    try {
      return fn();
    } finally {
      try { rmdirSync(lock); } catch { /* best effort */ }
    }
  }
}
