// Runs the detectors over real source trees: nearly every hit there is a false positive.
// usage: npm run corpus -- <dir> [<dir>...]   (prints the rule and location, never any part of a value)
import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import { findCandidates } from "../src/capture.ts";
import { scrubText } from "../src/scrub.ts";

const EXT = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".md", ".py", ".java", ".go", ".rs", ".yml", ".yaml", ".sh", ".css", ".html", ".toml", ".lock"]);
const SKIP = new Set([".git", ".next", "dist-newstyle"]);
const vault = { values: () => [], findByValue: () => undefined };
const roots = process.argv.slice(2);
let files = 0, bytes = 0, captureHits = 0, scrubHits = 0;
const examples = [];
const walk = (dir) => {
  for (const name of readdirSync(dir)) {
    if (SKIP.has(name)) continue;
    const p = join(dir, name);
    const st = statSync(p, { throwIfNoEntry: false });
    if (!st) continue;
    if (st.isDirectory()) { walk(p); continue; }
    if (!st.isFile() || !EXT.has(extname(name)) || st.size > 1_500_000) continue;
    const text = readFileSync(p, "utf8");
    files++; bytes += st.size;
    for (const c of findCandidates(text)) {
      captureHits++;
      if (examples.length < 400) examples.push(`capture ${c.confidence}/${c.hint ?? ""} ${p}:${text.slice(0, c.start).split("\n").length} len=${c.value.length}`);
    }
    const r = scrubText(text, vault, { shapes: true });
    scrubHits += r.hits;
    if (r.hits && examples.length < 400) examples.push(`scrub hits=${r.hits} ${p}`);
  }
};
for (const root of roots) walk(root);
console.log(`files=${files} MB=${(bytes / 1e6).toFixed(1)} captureHits=${captureHits} scrubHits=${scrubHits}`);
console.log(examples.join("\n"));
