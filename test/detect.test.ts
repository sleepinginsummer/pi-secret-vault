import { describe, expect, it } from "vitest";
import { findCandidates } from "../src/capture.ts";
import { envLineMode, maskEnvLines, scrubText } from "../src/scrub.ts";

const emptyVault = { values: () => [] as string[], findByValue: () => undefined };
const scrub = (text: string) => scrubText(text, emptyVault, { shapes: true }).text;
const captured = (text: string) => findCandidates(text).map((c) => c.value);

// Built at runtime so this file does not itself contain credential-shaped literals.
const fake = {
  github: `ghp_${"aB3dE6gH9jK2mN5pQ8sT1vW4yZ7cF0iL3oR6"}`,
  openai: `sk-proj-${"Ab3De6Gh9Jk2Mn5Pq8St1Vw4Yz7Cf0Il3Or6Ux9"}`,
  anthropic: `sk-ant-api03-${"Ab3De6Gh9Jk2Mn5Pq8St1Vw4Yz7Cf0Il3Or6Ux9"}`,
  aws: `AKIA${"Q3WE5RT7YU2IO4PA"}`,
  slack: `xoxb-${"123456789012-abcDEF123456"}`,
  gitlab: `glpat-${"aB3dE6gH9jK2mN5pQ8sT"}`,
  jwt: `${Buffer.from('{"alg":"HS256","typ":"JWT"}').toString("base64url")}.${Buffer.from('{"sub":"123"}').toString("base64url")}.c2lnbmF0dXJlLWJ5dGVz`,
  pem: `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----`,
};

const BENIGN = [
  "const token = getToken(user);",
  "const apiKey = await loadKey();",
  "token: session.accessToken,",
  "password: hashPassword(input),",
  "key: isAdmin ? adminKey : userKey,",
  '<Item key="sidebar-item-primary" />',
  '"max_tokens": 4096,',
  "tokenizer: cl100k_base",
  'cacheKey = "session:list:v3:project"',
  "sort_key: created_at_desc",
  '"passwordPlaceholder": "请输入新的登录密码"',
  'secret: "Shadow Mind Setting"',
  "令牌是用来鉴权的，不要写进日志",
  "密钥为空时返回错误code=401",
  "密码是否正确需要后端校验abc",
  "the token is expired-or-invalid",
  "password was reset2fa yesterday",
  "--token-limit 4096 --key-file ./a",
  "gh pr list --token $GH",
  "source_url: https://a.com/x?key=abc123def",
  "image_url=https://cdn.a.com/i.png?token=preview",
  "/_next/static/chunks/app-pages-internals-a1B2c3D4e5F6g7H8i9J0.js",
  "integrity sha512-Xy9Kq2Lm8Np4Rs7Tu1VwZa3Bc6De0Fg5Hi2Jk9Lm7Np4Qr8St1Uv6Wx3Yz0Ab5C==",
  "sha256:9f8e7d6c5b4a39281706f5e4d3c2b1a09f8e7d6c5b4a39281706f5e4d3c2b1a0",
  "msgId=01JCDE8ZQ4X7N2M5P9R3T6V8WA",
  "session V1StGXR8_Z5jdHi6B-myT7xQ2pLm ok",
  "01ARZ3NDEKTSV4RRFFQ69G5FAV",
  "clh3am8hi0000qwer1234abcd",
  "css-1a2b3c4d5e6f7g8h9i0jK_Lm",
  "task-management-feature-branch-name2",
  "risk-assessment-score-calculation-v2-final",
  "disk-usage-monitor-daemon-process-v2",
  "sk-task-management-feature-branch-name-with-long-words-v2",
  "AIDATESTNAMEABCDEFGH",
  `AKIA${"IOSFODNN7EXAMPLE"}`,
  "postgres://postgres:postgres@localhost:5432/app",
  "postgres://user:password@localhost/db",
  "https://user:${DB_PASS}@db.internal/app",
  "Bearer token is required for this route",
  "Authorization: Bearer ${TOKEN}",
  "eyJhbGciOi.eyJzdWIiOi.notreallyjson",
  // found by scanning real source trees (scripts/scan-corpus.mjs)
  "secret = store[configKeyName];",
  "Credential: ApiKeyCredential | OAuthCredential",
  "apiKey:options?.apiKey||getEnvApiKey(model.provider)",
  "credentials=ENV_SECRET_ACCESS_KEY",
  "PI_WEB_PASSWORD=足够长的随机字符串",
  "Password: &value,",
  "password = *m.Password",
];

describe("benign text stays untouched", () => {
  it.each(BENIGN)("%s", (text) => {
    expect(captured(text)).toEqual([]);
    expect(scrub(text)).toBe(text);
  });
});

describe("real formats are still recognised", () => {
  it.each(Object.entries(fake))("%s", (_name, value) => {
    expect(scrub(`x ${value} y`)).not.toContain(value);
    expect(captured(`x ${value} y`)).toContain(value);
  });

  it("masks the credential after an auth scheme", () => {
    const token = "aB3dE6gH9jK2mN5pQ8sT1vW4";
    expect(scrub(`Authorization: Bearer ${token}`)).not.toContain(token);
    expect(scrub(`curl -H "Bearer ${token}"`)).not.toContain(token);
  });

  it("masks only the password in a connection string", () => {
    const out = scrub("postgres://admin:s3cretPw9@db.internal/app");
    expect(out).toContain("postgres://admin:");
    expect(out).toContain("@db.internal/app");
    expect(out).not.toContain("s3cretPw9");
  });

  it("does not slice a token that sits inside a longer word", () => {
    expect(scrub(`prefix${fake.github}`)).toBe(`prefix${fake.github}`);
  });
});

describe("what a person types", () => {
  it.each([
    ["DB_PASSWORD=hunter22", "hunter22"],
    ["数据库密码是 Tr0ub4dor3", "Tr0ub4dor3"],
    ["密钥：aB3dE6gH9jK2mN5pQ8sT1", "aB3dE6gH9jK2mN5pQ8sT1"],
    ["mysql --password hunter22 -h host", "hunter22"],
    ["curl -u admin:p4ssw0rd https://x", "p4ssw0rd"],
    ["api_key=aB3dE6gH9jK2mN5pQ8sT1", "aB3dE6gH9jK2mN5pQ8sT1"],
  ])("%s", (text, value) => {
    expect(captured(text)).toContain(value);
  });

  it("entropy guesses exist only when asked for", () => {
    const text = "see qT7mZ2xK9pL4wR8vN3bC6yH1 there";
    expect(findCandidates(text)).toEqual([]);
    expect(findCandidates(text, { guess: true }).map((c) => c.confidence)).toEqual(["entropy"]);
  });
});

describe("credential files are masked by key name", () => {
  const env = ["DB_PASSWORD=hunter", "MAX_TOKENS=4096", "PWD=/home/me", "TOKEN_LIMIT=abcdefgh", "OPENAI_KEY=shortvalue", 'API_TOKEN="plainword"', "HOST=db.internal", "SECRET=${FROM_VAULT}"].join("\n");

  it("masks secrets and keeps settings", () => {
    const { text } = maskEnvLines(env, "whole");
    for (const hidden of ["hunter", "shortvalue", "plainword"]) expect(text).not.toContain(hidden);
    for (const kept of ["MAX_TOKENS=4096", "PWD=/home/me", "TOKEN_LIMIT=abcdefgh", "HOST=db.internal", "SECRET=${FROM_VAULT}"]) expect(text).toContain(kept);
  });

  it("source code is not a credential file", () => {
    const code = 'password = "abc12345"';
    expect(envLineMode("read", { path: "src/db.ts" })).toBeUndefined();
    expect(scrub(code)).toBe(code);
  });

  it("picks the mode from the tool call", () => {
    expect(envLineMode("read", { path: "/a/.env.local" })).toBe("whole");
    expect(envLineMode("read", { path: "/a/.env.example" })).toBeUndefined();
    expect(envLineMode("bash", { command: "printenv" })).toBe("whole");
    expect(envLineMode("bash", { command: "cat .env | head" })).toBe("whole");
    expect(envLineMode("bash", { command: "ls -la" })).toBe("prefixed");
  });

  it("grep only trusts lines attributed to a credential file", () => {
    expect(maskEnvLines("a/.env:3:DB_PASSWORD=hunter22", "prefixed").text).not.toContain("hunter22");
    const code = "src/a.ts:3:DB_PASSWORD=hunter22";
    expect(maskEnvLines(code, "prefixed").text).toBe(code);
  });
});

describe("config files judge the value too", () => {
  it("masks config values behind a read tool's line marker", () => {
    const env = "enzda│DB_PASSWORD=Env9x7Q2PassWd\nukadv│APP_NAME=demo-app";
    const envOut = maskEnvLines(env, "whole").text;
    expect(envOut).not.toContain("Env9x7Q2PassWd");
    expect(envOut).toContain("ukadv│APP_NAME=demo-app");
    expect(envOut.startsWith("enzda│DB_PASSWORD=")).toBe(true);
    const yml = "qxees│    username: demo\nheges│    password: Yml4k8W1PassWd\nneepl│  port: 8080";
    const ymlOut = maskEnvLines(yml, "config").text;
    expect(ymlOut).not.toContain("Yml4k8W1PassWd");
    expect(ymlOut).toContain("qxees│    username: demo");
    expect(ymlOut).toContain("neepl│  port: 8080");
    const grep = "=== conf/.env ===\n3:│ enzda│DB_PASSWORD=Env9x7Q2PassWd\n=== src/App.java ===\n9:│ tapkr│DB_PASSWORD=NotAttributed123";
    const grepOut = maskEnvLines(grep, "prefixed").text;
    expect(grepOut).not.toContain("Env9x7Q2PassWd");
    expect(grepOut).toContain("NotAttributed123");
    const code = "isvar│  password: hashPassword(input),\ntapkr│public class App {";
    expect(maskEnvLines(code, "prefixed").text).toBe(code);
  });

  it("masks a real password and leaves references alone", () => {
    const yml = ["spring:", "  datasource:", "    password: 1qaz2wsx!Q", "    username: app", "    other-password: ${DB_PASS}", "  access-key: aB3dE6gH9jK2mN5pQ8sT1vW4", "  token-limit: 4096"].join("\n");
    const { text } = maskEnvLines(yml, "config");
    expect(text).not.toContain("1qaz2wsx!Q");
    expect(text).not.toContain("aB3dE6gH9jK2mN5pQ8sT1vW4");
    for (const kept of ["username: app", "${DB_PASS}", "token-limit: 4096"]) expect(text).toContain(kept);
  });
  it("picks config mode from the path", () => {
    expect(envLineMode("read", { path: "src/main/resources/application-prod.yml" })).toBe("config");
    expect(envLineMode("bash", { command: "cat config/app.yaml" })).toBe("config");
    expect(envLineMode("read", { path: "src/db.ts" })).toBeUndefined();
  });
});

describe("vault values", () => {
  const vault = { values: () => ["abc123"], findByValue: (v: string) => (v === "abc123" ? { name: "short" } : undefined) };
  it("a short value only matches as a whole token", () => {
    expect(scrubText("x abc123 y", vault, { shapes: false }).text).toBe("x {{sec:short}} y");
    expect(scrubText("xabc1234", vault, { shapes: false }).text).toBe("xabc1234");
  });
});
