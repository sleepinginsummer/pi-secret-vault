import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { applyRemark } from "../persist.ts";
import { REMARK_GUIDE } from "../remark.ts";
import type { Vault } from "../vault.ts";

/**
 * Lets the model describe a credential for later sessions. It writes metadata only and can never
 * reach a value. A remark outlives the session, so every change is shown to the user with its old
 * and new text; that notice goes through ctx.ui.notify and never enters the transcript.
 */
export function createSecRemarkTool(getVault: () => Vault): ToolDefinition {
  return {
    name: "sec_remark",
    label: "sec_remark",
    description:
      `Add, change or clear the remark on a secret, so this and later sessions can tell what it is for and reuse it. ${REMARK_GUIDE} An empty remark clears it.`,
    promptSnippet: "Add or change the remark that says what a {{sec:NAME}} credential is for",
    promptGuidelines: [
      `After a credential has worked, call sec_remark if its remark is missing or out of date. ${REMARK_GUIDE}`,
    ],
    parameters: Type.Object({
      name: Type.String({ description: "The secret's NAME as listed by sec_list, without the sec: prefix or braces." }),
      remark: Type.String({ description: `The new remark. ${REMARK_GUIDE} An empty string clears it.` }),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const name = String((params as { name?: unknown }).name ?? "").trim().replace(/^sec:/, "");
      const result = applyRemark(getVault(), name, String((params as { remark?: unknown }).remark ?? ""));
      if (!result.ok) {
        return {
          content: [{ type: "text" as const, text: `sec_remark failed: ${result.reason}` }],
          details: { name, ok: false },
        };
      }
      if (ctx.hasUI && result.previous !== result.remark) {
        ctx.ui.notify(`The agent changed the remark on sec:${name}\nwas: ${result.previous ?? "(none)"}\nnow: ${result.remark ?? "(none)"}`, "info");
      }
      const scope = result.persisted ? "saved for every session" : "kept for this session only, because this secret is not saved";
      return {
        content: [{
          type: "text" as const,
          text: result.remark ? `remark on ${name} is now: ${result.remark} (${scope})` : `remark on ${name} cleared (${scope})`,
        }],
        details: { name, ok: true },
      };
    },
  } as ToolDefinition;
}
