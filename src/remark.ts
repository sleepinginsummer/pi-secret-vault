import { looksCredentialish, looksLikeIdentifierText } from "./entropy.ts";
import { findRefs } from "./refs.ts";
import { scrubText } from "./scrub.ts";
import type { Vault } from "./vault.ts";

export const MAX_REMARK_CHARS = 200;

/**
 * What a good remark holds. Shared by every tool description, so the model is told the same
 * thing wherever it can write one. The example must survive the scrubber (pinned by a test).
 */
export const REMARK_GUIDE =
  `Keep a remark short (one line, at most ${MAX_REMARK_CHARS} characters) and say what the credential is for: the usage scenario, the URL or host, and the username when it has to be used together with one. ` +
  "Example: company Jenkins deploys · https://jenkins.example.com · username deploy. " +
  "Never put a password, token or key in it, nor a URL with embedded credentials, nor a {{sec:NAME}} ref.";

const URL_WITH_PASSWORD = /[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i;
const CREDENTIAL_QUERY = /[?&](?:token|key|secret|password|passwd|pwd|api[_-]?key|access[_-]?token|auth)=/i;

/** One line, no control characters. Also applied on display, because the file can be edited by hand. */
export function normalizeRemark(raw: string): string {
  return raw
    .replace(/\s*[\r\n]+\s*/g, " ")
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]/g, " ")
    .trim();
}

/**
 * A remark is plaintext on disk and goes to the provider in every `sec_list`, so nothing
 * credential-shaped may become one. Refusal reasons never quote the input.
 */
export function validateRemark(raw: string, vault: Vault): { ok: true; remark: string | undefined } | { ok: false; reason: string } {
  const remark = normalizeRemark(raw);
  if (!remark) return { ok: true, remark: undefined };
  const refuse = (why: string) => ({ ok: false as const, reason: `remark refused: ${why} Nothing was changed.` });
  if ([...remark].length > MAX_REMARK_CHARS) return refuse(`it is longer than ${MAX_REMARK_CHARS} characters.`);
  if (findRefs(remark).length) return refuse("it contains a {{sec:NAME}} ref, which would put the real value in plaintext.");
  if (URL_WITH_PASSWORD.test(remark)) return refuse("it contains a URL with an embedded password. Write the URL and the username separately.");
  if (CREDENTIAL_QUERY.test(remark)) return refuse("it contains a URL with a credential in its query string. Remove the query string.");
  const looksSecret = scrubText(remark, vault, { shapes: true }).hits > 0
    || remark.split(/[\s·,，;；|]+/).some((token) => looksCredentialish(token) && !looksLikeIdentifierText(token));
  if (looksSecret) return refuse("it looks like it contains a credential. Describe the credential, do not include it.");
  return { ok: true, remark };
}
