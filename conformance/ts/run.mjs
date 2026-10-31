// Schema-level verdict per fixture using Ajv (JSON Schema 2020-12), independent of the Python validator.
import fs from "node:fs"; import path from "node:path";
import Ajv2020 from "ajv/dist/2020.js";
const root = path.resolve(import.meta.dirname, "../..");
const ajv = new Ajv2020({ strict: false, allErrors: false });
const v = {};
for (const f of fs.readdirSync(path.join(root, "schemas"))) {
  const kind = f.replace(".schema.json", ""); v[kind] = ajv.compile(JSON.parse(fs.readFileSync(path.join(root, "schemas", f), "utf8")));
}
const out = {}; const base = path.join(root, "tests/fixtures");
const walk = d => fs.readdirSync(d, { withFileTypes: true }).flatMap(e => e.isDirectory() ? walk(path.join(d, e.name)) : [path.join(d, e.name)]);
for (const f of walk(base).sort()) {
  const kind = path.basename(path.dirname(f)); const doc = JSON.parse(fs.readFileSync(f, "utf8"));
  out[path.relative(base, f).split(path.sep).join("/")] = v[kind](doc) === true;
}
console.log(JSON.stringify(Object.fromEntries(Object.entries(out).sort()), null, 1));
