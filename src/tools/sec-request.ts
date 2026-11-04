import type { ToolDefinition } from "@earendil-works/pi-coding-agent";
import { Type } from "typebox";
import { isValidName } from "../refs.ts";
import { promptMaskedSecret } from "../masked-input.ts";
import { saveSecret } from "../persist.ts";
import type { Vault } from "../vault.ts";

/** 与 /sec add 的单值上限保持同一量级：超过这个长度几乎不可能是凭证。 */
const MAX_SECRET_BYTES = 16 * 1024;

/**
 * 让模型可以**主动请求**一个凭证，而值只落在 vault 里。
 *
 * 这是 pi-secret 原本缺的一环：它的 `sec_list` 只能列出已有的名字，模型无法要求
 * 用户补充缺的那个（secret-request 用 `secret_env.request` 补上了这一点，但它
 * 绑死 macOS Keychain，且 RPC 模式下掩码组件渲染不出来）。
 *
 * 安全边界（与 pi-secret 其余部分一致）：
 * - 返回值里只有名字和状态，**永不包含值**，details 也一样（details 会被持久化）。
 * - 值拿到后直接存进 vault，之后只能通过 `{{sec:NAME}}` 在执行期展开。
 * - 取消 / 空输入 / 校验失败都返回明确原因，但不回显用户键入的内容。
 */
export function createSecRequestTool(getVault: () => Vault): ToolDefinition {
  return {
    name: "sec_request",
    label: "sec_request",
    description:
      "Ask the user to enter a credential that is missing for the current task. The value goes straight into this session's vault and is never returned to you: you only learn whether it was provided, and then use it as {{sec:NAME}}.",
    promptSnippet: "Ask the user for a missing credential (masked input; you never see the value)",
    promptGuidelines: [
      "Call sec_request when a task needs a credential that sec_list does not list. Never ask the user to paste a secret into the conversation, and never guess, generate or request one another way.",
      "A sec_request result tells you only provided / cancelled / reused. Do not ask the user what they typed, and do not try to read it back: use {{sec:NAME}} where the credential is needed.",
    ],
    parameters: Type.Object({
      name: Type.String({
        description: `Reference name for the credential, lower-case letters, digits, underscores or dashes, starting with a letter (e.g. github_token). Used later as {{sec:NAME}}.`,
      }),
      reason: Type.Optional(
        Type.String({ description: "One short sentence telling the user what the credential is for. Shown in the prompt." }),
      ),
    }),
    async execute(_toolCallId, params, _signal, _onUpdate, ctx) {
      const name = String((params as { name?: unknown }).name ?? "").trim();
      if (!isValidName(name)) {
        return {
          content: [
            {
              type: "text" as const,
              text: 'sec_request failed: invalid name. Use lower-case letters, digits, "_" or "-", starting with a letter, at most 64 characters.',
            },
          ],
          details: { name, ok: false, error: "invalid-name" },
        };
      }

      const vault = getVault();
      if (vault.has(name)) {
        return {
          content: [
            {
              type: "text" as const,
              text: `reused: ${name} is already in the vault. Reference it as {{sec:${name}}}.`,
            },
          ],
          details: { name, ok: true, reused: true },
        };
      }

      const reason = String((params as { reason?: unknown }).reason ?? "").trim();
      const title = reason ? `Secret for ${name} — ${reason}` : `Secret for ${name}`;

      // TUI 有圆点组件；RPC / 其他有 UI 的宿主退回到 ctx.ui.input + 约定标记。
      // 无 UI（json / print 模式）时 ctx.hasUI 为 false，直接报告不可用而不是静默挂起。
      if (!ctx.hasUI) {
        return {
          content: [
            {
              type: "text" as const,
              text: `cancelled: ${name} was not provided — this host has no UI to ask for a credential. Ask the user to run /sec add ${name}.`,
            },
          ],
          details: { name, ok: false, error: "no-ui" },
        };
      }

      const entered = await promptMaskedSecret(ctx, title);

      if (entered === undefined || entered.trim() === "") {
        return {
          content: [
            {
              type: "text" as const,
              text: `cancelled: ${name} was not provided. Do not retry sec_request for the same name unless the user asks.`,
            },
          ],
          details: { name, ok: false, error: "cancelled" },
        };
      }
      if (Buffer.byteLength(entered, "utf8") > MAX_SECRET_BYTES) {
        return {
          content: [
            {
              type: "text" as const,
              text: `sec_request failed: the value for ${name} is too long (limit ${MAX_SECRET_BYTES} bytes). The value was discarded, not stored.`,
            },
          ],
          details: { name, ok: false, error: "too-long" },
        };
      }

      // 注意：这里不 trim 值本身——凭证可能以后导空格结尾。
      const saved = saveSecret(vault, name, entered, "prompt");
      return {
        content: [
          {
            type: "text" as const,
            text: `provided: ${name} is ${saved.persisted ? "saved in the vault" : "in this session's vault"}. Reference it as {{sec:${name}}}.`,
          },
        ],
        details: { name, ok: true, reused: false },
      };
    },
  } as ToolDefinition;
}
