/* =====================================================================
 *  Luau obfuscator — reliable, multi-layer.
 *
 *  Pipeline (every build is randomized):
 *    1. Lex Luau into tokens (robust: long strings, comments, Luau numbers,
 *       string interpolation, compound operators).
 *    2. Minify (drop comments, collapse whitespace).
 *    3. Encrypt every string and number literal into a per-literal cipher,
 *       decrypted at runtime through D() -> dec() (xorshift keystream).
 *    4. Capture the globals the runtime needs into locals (immune to the
 *       user shadowing string/tonumber/bit32/etc).
 *    5. Inject junk locals.
 *    6. Wrap the whole chunk in N encrypted loader layers, each a different
 *       key, the outer one carrying an anti-tamper + integrity guard.
 *
 *  It never changes program behaviour: literals decrypt back to the exact
 *  original bytes, everything else is passed through untouched. If anything
 *  about the input can't be lexed, obfuscate() throws and the caller falls
 *  back to delivering the plain source.
 *
 *  Not a bytecode VM (that needs the Luau compiler). This raises the cost of
 *  reading/dumping a script a great deal; it does not make it impossible.
 * ===================================================================== */

import luaparse from "luaparse";
import { rnd32, cipherB64, decLua } from "./cipher.js";
import { compileToVM } from "./obfvm.js";

const WORD = /[A-Za-z0-9_]/;
const COMBINER = /[-.:=<>~/]/; // chars that must not touch and accidentally form --, .., ::, ==, <=, //, ~=

/* ------------------------------------------------------------------ *
 *  Pass 0: scope-correct local renaming (AST-driven, surgical).
 *
 *  Parse to a real syntax tree, work out exactly which identifiers are
 *  value-locals (and their byte ranges), then rewrite only those spans in
 *  the original text. No reprinting -> behaviour can't change. Throws on
 *  anything it can't parse (Luau types, continue, +=, `...`), and the
 *  caller then skips renaming.
 * ------------------------------------------------------------------ */

function renameLocals(src) {
  const ast = luaparse.parse(src, { ranges: true, luaversion: "5.3", comments: false, scope: false });
  const edits = [];
  const prefix = "_" + rnd32().toString(36).slice(0, 4);
  let counter = 0;
  const scopes = [];
  const push = () => scopes.push(new Map());
  const pop = () => scopes.pop();
  const declare = (node) => {
    if (!node || node.type !== "Identifier" || node.name === "self") return; // never rename implicit self
    const nn = prefix + (counter++).toString(36);
    scopes[scopes.length - 1].set(node.name, nn);
    edits.push({ s: node.range[0], e: node.range[1], name: nn });
  };
  const resolve = (node) => {
    for (let i = scopes.length - 1; i >= 0; i--) {
      if (scopes[i].has(node.name)) { edits.push({ s: node.range[0], e: node.range[1], name: scopes[i].get(node.name) }); return; }
    }
  };
  const list = (arr) => { for (const n of arr || []) expr(n); };
  const block = (stmts) => { for (const s of stmts || []) stmt(s); };
  const scoped = (fn) => { push(); fn(); pop(); };

  function expr(e) {
    if (!e) return;
    switch (e.type) {
      case "Identifier": resolve(e); break;
      case "NumericLiteral": case "StringLiteral": case "BooleanLiteral": case "NilLiteral": case "VarargLiteral": break;
      case "BinaryExpression": case "LogicalExpression": expr(e.left); expr(e.right); break;
      case "UnaryExpression": expr(e.argument); break;
      case "MemberExpression": expr(e.base); break;                 // .identifier is a field, not a var
      case "IndexExpression": expr(e.base); expr(e.index); break;
      case "CallExpression": expr(e.base); list(e.arguments); break;
      case "TableCallExpression": expr(e.base); expr(e.arguments); break;
      case "StringCallExpression": expr(e.base); break;             // string argument has no vars
      case "FunctionDeclaration": // anonymous function expression
        scoped(() => { for (const p of e.parameters) if (p.type === "Identifier") declare(p); block(e.body); });
        break;
      case "TableConstructorExpression":
        for (const f of e.fields) {
          if (f.type === "TableKey") { expr(f.key); expr(f.value); }
          else if (f.type === "TableKeyString") { expr(f.value); } // key is a field name
          else expr(f.value); // TableValue
        }
        break;
      default: throw new Error("unknown expr " + e.type);
    }
  }

  function stmt(s) {
    switch (s.type) {
      case "LocalStatement": list(s.init); for (const v of s.variables) declare(v); break; // init resolves before decl (local x = x)
      case "AssignmentStatement": list(s.variables); list(s.init); break;
      case "CallStatement": expr(s.expression); break;
      case "ReturnStatement": list(s.arguments); break;
      case "FunctionDeclaration":
        if (s.isLocal) declare(s.identifier);
        else expr(s.identifier); // a.b.c:d -> rename base if local, fields/method skipped
        scoped(() => { for (const p of s.parameters) if (p.type === "Identifier") declare(p); block(s.body); });
        break;
      case "IfStatement":
        for (const c of s.clauses) { if (c.condition) expr(c.condition); scoped(() => block(c.body)); }
        break;
      case "ForNumericStatement":
        expr(s.start); expr(s.end); expr(s.step);
        scoped(() => { declare(s.variable); block(s.body); });
        break;
      case "ForGenericStatement":
        list(s.iterators);
        scoped(() => { for (const v of s.variables) declare(v); block(s.body); });
        break;
      case "WhileStatement": expr(s.condition); scoped(() => block(s.body)); break;
      case "DoStatement": scoped(() => block(s.body)); break;
      case "RepeatStatement": scoped(() => { block(s.body); expr(s.condition); }); break; // until sees body locals
      case "BreakStatement": case "GotoStatement": case "LabelStatement": break;
      default: throw new Error("unknown stmt " + s.type);
    }
  }

  scoped(() => block(ast.body));

  edits.sort((a, b) => b.s - a.s);
  let out = src;
  for (const ed of edits) out = out.slice(0, ed.s) + ed.name + out.slice(ed.e);
  return out;
}

/* ------------------------------------------------------------------ *
 *  Lexer
 * ------------------------------------------------------------------ */

function lex(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  const push = (t, a, b) => toks.push({ t, s: a, e: b });

  const longBracket = (start) => {
    // at src[start] === '[' ; returns end index after closing ]==] or -1
    let j = start + 1, lvl = 0;
    while (src[j] === "=") { lvl++; j++; }
    if (src[j] !== "[") return -1;
    const close = "]" + "=".repeat(lvl) + "]";
    const idx = src.indexOf(close, j + 1);
    return idx === -1 ? n : idx + close.length;
  };

  while (i < n) {
    const c = src[i];

    // whitespace
    if (c === " " || c === "\t" || c === "\r" || c === "\n" || c === "\f" || c === "\v") {
      let j = i + 1;
      while (j < n && " \t\r\n\f\v".includes(src[j])) j++;
      push("ws", i, j); i = j; continue;
    }

    // comments
    if (c === "-" && src[i + 1] === "-") {
      if (src[i + 2] === "[") {
        const end = longBracket(i + 2);
        if (end !== -1) { push("comment", i, end); i = end; continue; }
      }
      let j = i + 2;
      while (j < n && src[j] !== "\n") j++;
      push("comment", i, j); i = j; continue;
    }

    // long string
    if (c === "[" && (src[i + 1] === "[" || src[i + 1] === "=")) {
      const end = longBracket(i);
      if (end !== -1) { push("lstring", i, end); i = end; continue; }
    }

    // short string
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === c) { j++; break; }
        if (src[j] === "\n") break; // unterminated; let it error naturally
        j++;
      }
      push("sstring", i, j); i = j; continue;
    }

    // interpolated string (Luau backticks) — passed through untouched
    if (c === "`") {
      let j = i + 1, depth = 0;
      while (j < n) {
        if (src[j] === "\\") { j += 2; continue; }
        if (src[j] === "{") { depth++; j++; continue; }
        if (src[j] === "}") { if (depth > 0) depth--; j++; continue; }
        if (src[j] === "`" && depth === 0) { j++; break; }
        j++;
      }
      push("interp", i, j); i = j; continue;
    }

    // number
    if (c >= "0" && c <= "9" || (c === "." && src[i + 1] >= "0" && src[i + 1] <= "9")) {
      let j = i;
      if (c === "0" && (src[i + 1] === "x" || src[i + 1] === "X")) {
        j += 2;
        while (j < n && /[0-9a-fA-F_.]/.test(src[j])) j++;
        if (src[j] === "p" || src[j] === "P") { j++; if (src[j] === "+" || src[j] === "-") j++; while (j < n && /[0-9_]/.test(src[j])) j++; }
      } else if (c === "0" && (src[i + 1] === "b" || src[i + 1] === "B")) {
        j += 2;
        while (j < n && /[01_]/.test(src[j])) j++;
      } else {
        while (j < n && /[0-9_.]/.test(src[j])) j++;
        if (src[j] === "e" || src[j] === "E") { j++; if (src[j] === "+" || src[j] === "-") j++; while (j < n && /[0-9_]/.test(src[j])) j++; }
      }
      push("number", i, j); i = j; continue;
    }

    // name / keyword
    if (/[A-Za-z_]/.test(c)) {
      let j = i + 1;
      while (j < n && WORD.test(src[j])) j++;
      push("name", i, j); i = j; continue;
    }

    // operators / punctuation — longest match
    const three = src.substr(i, 3);
    const two = src.substr(i, 2);
    if (three === "..." || three === "..=") { push("op", i, i + 3); i += 3; continue; }
    if (["==", "~=", "<=", ">=", "..", "::", "//", "+=", "-=", "*=", "/=", "%=", "^=", "->"].includes(two)) { push("op", i, i + 2); i += 2; continue; }
    push("op", i, i + 1); i += 1;
  }
  return toks;
}

/* ------------------------------------------------------------------ *
 *  Decode a Luau short-string literal body to raw bytes
 * ------------------------------------------------------------------ */

function utf8(cp) {
  if (cp < 0x80) return [cp];
  if (cp < 0x800) return [0xc0 | (cp >> 6), 0x80 | (cp & 0x3f)];
  if (cp < 0x10000) return [0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f)];
  return [0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f)];
}

function unescape(body) {
  const out = [];
  const enc = new TextEncoder();
  for (let i = 0; i < body.length; ) {
    const c = body[i];
    if (c !== "\\") { for (const b of enc.encode(c)) out.push(b); i++; continue; }
    const d = body[i + 1];
    const simple = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, "\\": 92, '"': 34, "'": 39, "\n": 10 };
    if (d in simple) { out.push(simple[d]); i += 2; continue; }
    if (d === "x") { out.push(parseInt(body.substr(i + 2, 2), 16) || 0); i += 4; continue; }
    if (d === "z") { i += 2; while (i < body.length && " \t\r\n\f\v".includes(body[i])) i++; continue; }
    if (d === "u" && body[i + 2] === "{") { const end = body.indexOf("}", i + 3); for (const b of utf8(parseInt(body.slice(i + 3, end), 16) || 0)) out.push(b); i = end + 1; continue; }
    if (d >= "0" && d <= "9") { let k = i + 1, s = ""; while (k < body.length && s.length < 3 && /[0-9]/.test(body[k])) { s += body[k]; k++; } out.push(parseInt(s, 10) & 0xff); i = k; continue; }
    for (const b of enc.encode(d)) out.push(b); i += 2; // unknown escape: keep the char
  }
  return Uint8Array.from(out);
}

/* cipherB64 / rnd32 / decLua now live in ./cipher.js (shared with the VM). */

/* ------------------------------------------------------------------ *
 *  Emit with minimal, safe spacing
 * ------------------------------------------------------------------ */

function joiner() {
  let out = "", last = "";
  return {
    add(piece) {
      if (!piece) return;
      const f = piece[0];
      if (last && ((WORD.test(last) && WORD.test(f)) || (COMBINER.test(last) && COMBINER.test(f)))) out += " ";
      out += piece;
      last = piece[piece.length - 1];
    },
    get() { return out; },
  };
}

/* ------------------------------------------------------------------ *
 *  Main
 * ------------------------------------------------------------------ */

function transform(src, master, names) {
  const toks = lex(src);
  const j = joiner();

  // index of previous significant (non-ws/comment) token, to detect call sugar  f"x" / f[[x]]
  let prevSig = null;
  const sigType = (k) => (k && k.t) || "";

  const encLiteral = (bytes) => {
    const salt = rnd32();
    const seed = (master ^ salt) >>> 0;
    return `${names.D}("${cipherB64(bytes, seed)}",${salt})`;
  };

  for (let idx = 0; idx < toks.length; idx++) {
    const tk = toks[idx];
    const raw = src.slice(tk.s, tk.e);

    if (tk.t === "ws" || tk.t === "comment") continue;

    if (tk.t === "sstring" || tk.t === "lstring") {
      let bytes;
      if (tk.t === "sstring") {
        bytes = unescape(raw.slice(1, -1));
      } else {
        let inner = raw.replace(/^\[=*\[/, "").replace(/\]=*\]$/, "");
        if (inner[0] === "\n") inner = inner.slice(1); // Lua drops a leading newline in long strings
        else if (inner[0] === "\r") inner = inner.replace(/^\r\n?/, "");
        bytes = new TextEncoder().encode(inner);
      }
      // call sugar:  f"x" / f[[x]] / obj:m"x"  -> wrap so  f(D(..))  stays a valid call
      const sugar = ["name", "sstring", "lstring"].includes(sigType(prevSig)) ||
        (prevSig && prevSig.t === "op" && [")", "]", "}"].includes(src.slice(prevSig.s, prevSig.e)));
      j.add(sugar ? `(${encLiteral(bytes)})` : encLiteral(bytes));
      prevSig = tk; continue;
    }

    if (tk.t === "number") {
      const text = raw.replace(/_/g, ""); // strip Luau digit separators -> portable numeral
      j.add(`${names.tn}(${encLiteral(new TextEncoder().encode(text))})`);
      prevSig = tk; continue;
    }

    // name / op / interp / keyword — passed through verbatim
    j.add(raw);
    prevSig = tk;
  }

  return j.get();
}

function junk(names) {
  const lines = [];
  const k = 2 + (rnd32() % 3);
  for (let i = 0; i < k; i++) {
    lines.push(`local ${names.junk()}=${rnd32()}`);
  }
  return lines.join(" ");
}

// Build the self-contained inner chunk: runtime + decryptor + captured globals + code.
function buildInner(src, master, names) {
  const code = transform(src, master, names);
  return [
    decLua(names.dec),
    `local ${names.bx}=bit32.bxor`,
    `local ${names.tn}=tonumber`,
    `local ${names.master}=${master}`,
    `local function ${names.D}(d,s) return ${names.dec}(d,${names.bx}(${names.master},s)) end`,
    junk(names),
    code,
  ].join("\n");
}

// Wrap a chunk in one encrypted loader layer.
function wrapLayer(inner, decName, withGuard) {
  const seed = rnd32() || 0x1234abcd;
  const b64 = cipherB64(new TextEncoder().encode(inner), seed);
  const guard = withGuard
    ? `local ic=iscclosure if ic then local lc=(loadstring or load) if lc~=nil and ic(lc)==false then return end end `
    : "";
  return `${decLua(decName)}
local _L=(loadstring or load) ${guard}
local _f=_L(${decName}([==[${b64}]==],${seed}))
if _f then return _f(...) end`;
}

/**
 * Obfuscate Luau source. Throws if the input can't be processed; callers
 * should fall back to the plain source on throw.
 * @param {string} src
 * @param {{layers?: number}} [opts]
 */
export function obfuscate(src, opts = {}) {
  if (typeof src !== "string" || src.trim() === "") return src;
  const layers = Math.max(1, Math.min(4, opts.layers ?? 2));
  const master = rnd32();

  let counter = 0;
  const nm = () => "_" + (counter++).toString(36) + (rnd32() % 1000).toString(36);
  const names = { dec: nm(), D: nm(), bx: nm(), tn: nm(), master: nm(), junk: nm };

  // Tier 1: compile to the bytecode VM (logic becomes opcodes). Falls back to
  // Tier 2 (rename + constant encryption) for anything the VM can't compile yet.
  let inner = null;
  if (opts.vm !== false) {
    try { inner = compileToVM(src); } catch { inner = null; }
  }
  if (inner == null) {
    let code = src;
    if (opts.rename !== false) { try { code = renameLocals(src); } catch { code = src; } }
    inner = buildInner(code, master, names);
  }

  let out = inner;
  for (let i = 0; i < layers; i++) out = wrapLayer(out, nm(), i === layers - 1);
  return out;
}

export { renameLocals };
