// Registry <-> sidebar sync, and the palette's search behaviour.
const fs = require("fs");
const path = require("path");
const ROOT = path.join(__dirname, "..");
const registrySrc = fs.readFileSync(path.join(ROOT, "src/lib/navRegistry.js"), "utf8");
const sidebarSrc = fs.readFileSync(path.join(ROOT, "src/components/Sidebar.jsx"), "utf8");
function assert(c, m) { if (!c) { console.error("FAIL: " + m); process.exit(1); } }

const registryRoutes = [...registrySrc.matchAll(/to:\s*"([^"]+)"/g)].map((m) => m[1]);
const sidebarRoutes = [...sidebarSrc.matchAll(/NavItem\s+to="([^"]+)"/g)].map((m) => m[1]);
assert(sidebarRoutes.length > 30, `sidebar route count ${sidebarRoutes.length}`);
const missing = sidebarRoutes.filter((r) => !registryRoutes.includes(r));
assert(missing.length === 0, `sidebar routes missing from registry: ${missing.join(", ")}`);
console.log(`PASS: all ${sidebarRoutes.length} sidebar routes are present in the nav registry — palette and sidebar cannot drift`);
const extra = registryRoutes.filter((r) => !sidebarRoutes.includes(r));
assert(extra.length === 0, `dead registry routes: ${extra.join(", ")}`);
console.log("PASS: every registry entry is a real sidebar destination — no dead palette results");
const dupes = registryRoutes.filter((r, i) => registryRoutes.indexOf(r) !== i);
assert(dupes.length === 0, `duplicate routes: ${[...new Set(dupes)].join(", ")}`);
console.log("PASS: no duplicate destinations in the registry");

const babel = require("/tmp/babelcheck/node_modules/@babel/core");
const code = babel.transformSync(registrySrc, {
  presets: [require("/tmp/babelcheck/node_modules/@babel/preset-react")],
  plugins: [require("/tmp/babelcheck/node_modules/@babel/plugin-transform-modules-commonjs")],
}).code;
const mod = { exports: {} };
new Function("module", "exports", "require", code)(mod, mod.exports, require);
const { searchNav } = mod.exports;
const all = (q) => searchNav(q, null).map((r) => r.label);

assert(all("dmarc")[0] === "Email Authentication", `"dmarc" -> ${all("dmarc")[0]}`);
assert(all("edr").includes("Directory"), `"edr" -> ${all("edr").join(", ")}`);
assert(all("sbom").includes("SBOM / Dependencies") && all("sbom").includes("Container Image Scanning"), "sbom");
console.log("PASS: keyword search finds pages by what people call them — dmarc->Email Auth, edr->Directory, sbom->SBOM+Container");
assert(all("find")[0] === "Findings", `"find" -> ${all("find")[0]}`);
console.log("PASS: a label prefix ranks above a keyword mention — 'find' -> Findings first");
assert(all("scr").includes("Secrets Scanning"), `"scr" -> ${all("scr").join(", ")}`);
console.log("PASS: fuzzy subsequence works — 'scr' reaches Secrets Scanning");
const restricted = (q) => searchNav(q, (to) => !to.startsWith("/admin")).map((r) => r.to);
assert(!restricted("").some((to) => to.startsWith("/admin")), "leaked /admin route");
assert(restricted("").includes("/findings"), "permitted route hidden");
console.log("PASS: the palette hides destinations a role can't access — never offers a jump that 403s");
assert(searchNav("", null).length === registryRoutes.length, "empty query count");
console.log("PASS: an empty query lists every destination");
