// Static preview (P6-06..P6-08). ADVISORY ONLY: it can never prove a program makes no other calls; enforcement is at runtime per call.
import { parse } from "acorn"; import { ancestor } from "acorn-walk";
let src = ""; for await (const c of process.stdin) src += c;
const { code } = JSON.parse(src);
const REFLECT = new Set(["eval", "Function", "require", "import", "globalThis", "global", "this", "Reflect", "Proxy", "constructor", "__proto__", "prototype", "process", "Object", "setTimeout", "setInterval"]);
const res = { calls: [], unknown: [], parse_error: null };
let ast; try { ast = parse(`(async function(){\n${code}\n})`, { ecmaVersion: "latest", locations: true, allowReturnOutsideFunction: true }); }
catch (e) { res.parse_error = String(e.message).slice(0, 200); res.unknown.push({ reason: "unparseable_program", line: 0 }); console.log(JSON.stringify({ ...res, verdict: "PARTIAL_PREVIEW", exhaustive: false })); process.exit(0); }
const line = (n) => (n.loc ? n.loc.start.line - 1 : 0);
const chain = (n) => { const p = []; while (n.type === "MemberExpression") { if (n.computed) return null; p.unshift(n.property.name); n = n.object; } return n.type === "Identifier" && n.name === "tools" ? p : null; };
const direct = new Set();
ancestor(ast, { CallExpression(n) { const c = n.callee.type === "MemberExpression" ? chain(n.callee) : null; if (c && c.length) { direct.add(n.callee); res.calls.push({ name: c.join("."), line: line(n) }); }
  if (n.callee.type === "Import") res.unknown.push({ reason: "dynamic_import", line: line(n) }); } });      // pass 1 (post-order walk would otherwise see callees before their calls)
ancestor(ast, {
  MemberExpression(n, _s, anc) {
    if (!n.computed && ["constructor", "__proto__", "prototype"].includes(n.property.name)) res.unknown.push({ reason: `reflective_property:${n.property.name}`, line: line(n) });
    // walk up: is this the callee of a direct call? if the chain root is `tools` but it is not a direct call -> escapes (alias, computed, property read)
    let root = n; while (root.type === "MemberExpression") root = root.object;
    if (root.type === "Identifier" && root.name === "tools" && !direct.has(n) && !anc.some((a) => direct.has(a))) {
      if (n.computed) res.unknown.push({ reason: "computed_tools_access", line: line(n) });
      else if (!anc.some((a) => a.type === "MemberExpression" && a !== n && direct.has(a))) res.unknown.push({ reason: "tools_member_not_called_directly", line: line(n) }); }
    if (n.computed && n.property.type !== "Literal") res.unknown.push({ reason: "computed_member_access", line: line(n) });
  },
  Identifier(n, _s, anc) {
    const p = anc[anc.length - 2];
    if (n.name === "tools" && !(p && p.type === "MemberExpression" && p.object === n)) res.unknown.push({ reason: "tools_referenced_without_member (alias/destructure/argument)", line: line(n) });
    if (REFLECT.has(n.name) && !(p && p.type === "MemberExpression" && p.property === n && !p.computed && !["constructor", "__proto__", "prototype"].includes(n.name))) res.unknown.push({ reason: `reflective_or_host_identifier:${n.name}`, line: line(n) });
  },
  ImportExpression(n) { res.unknown.push({ reason: "dynamic_import", line: line(n) }); },
  ThisExpression(n) { res.unknown.push({ reason: "this", line: line(n) }); },
  MemberProperty() {},
  WithStatement(n) { res.unknown.push({ reason: "with_statement", line: line(n) }); },
  TemplateLiteral() {},
});
const seen = new Set(); res.unknown = res.unknown.filter((u) => { const k = u.reason + u.line; if (seen.has(k)) return false; seen.add(k); return true; });
console.log(JSON.stringify({ ...res, verdict: "PARTIAL_PREVIEW", exhaustive: false, note: "static preview is never a complete list of calls; every runtime call is still mediated" }));
