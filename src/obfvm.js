/* =====================================================================
 *  Bytecode VM obfuscator.
 *
 *  compileToVM(src) parses Lua, compiles it to a custom stack-machine
 *  instruction set, and emits a self-contained Lua program: a small
 *  interpreter plus the (encrypted-constant) bytecode. The original control
 *  flow and expressions no longer exist as Lua — only opcodes + a dispatch
 *  loop. Runs in any Luau executor because the VM is ordinary Lua.
 *
 *  Throws on anything it can't compile yet (goto, bitwise/// operators, or
 *  an unknown node); the caller then falls back to the layered obfuscator,
 *  so a script is never broken.
 * ===================================================================== */

import luaparse from "luaparse";
import { rnd32, cipherB64, decLua } from "./cipher.js";

const OP = {
  LOADK: 1, LOADBOOL: 2, LOADNIL: 3, GETLOCAL: 4, SETLOCAL: 5, GETGLOBAL: 6, SETGLOBAL: 7,
  GETUPVAL: 8, SETUPVAL: 9, NEWTABLE: 10, GETINDEX: 11, SETINDEX: 12, BINOP: 13, UNOP: 14,
  NEWACC: 15, ACCPUSH: 16, CALL: 18, RETURN0: 20, RETURNACC: 21, JMP: 22, JMPIFNOT: 23,
  JMPIF: 24, POPTOP: 25, CLOSURE: 26, VARARGPACK: 28, UNPACK1: 30, ACCEXTEND: 31,
  ACCGET: 32, SETFIELDKEEP: 33, SETLISTMULTI: 34, GETVARARGN: 35, DUP: 36,
};

const BIN = { "+": 1, "-": 2, "*": 3, "/": 4, "%": 5, "^": 6, "..": 7, "==": 8, "~=": 9, "<": 10, "<=": 11, ">": 12, ">=": 13 };
const UN = { "-": 1, "not": 2, "#": 3 };

// Per-build: give every opcode a fresh random number, so no two obfuscated
// scripts share an instruction set (what defeats generic devirtualizers).
function makeOps() {
  const names = Object.keys(OP);
  const pool = Array.from({ length: 255 }, (_, i) => i + 1);
  for (let i = pool.length - 1; i > 0; i--) { const j = rnd32() % (i + 1); const t = pool[i]; pool[i] = pool[j]; pool[j] = t; }
  const m = {}; names.forEach((n, i) => (m[n] = pool[i])); return m;
}
function shuffle(arr) { const a = arr.slice(); for (let i = a.length - 1; i > 0; i--) { const j = rnd32() % (i + 1); const t = a[i]; a[i] = a[j]; a[j] = t; } return a; }
function uname(used) { let n; do { n = "_" + rnd32().toString(36).slice(0, 5); } while (used.has(n)); used.add(n); return n; }

/* ---------- byte decoding for string constants (keeps binary intact) ---------- */
function utf8(cp) {
  if (cp < 0x80) return [cp];
  if (cp < 0x800) return [0xc0 | (cp >> 6), 0x80 | (cp & 0x3f)];
  if (cp < 0x10000) return [0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f)];
  return [0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f)];
}
function unescapeBytes(body) {
  const out = [], enc = new TextEncoder();
  for (let i = 0; i < body.length;) {
    const c = body[i];
    if (c !== "\\") { for (const b of enc.encode(c)) out.push(b); i++; continue; }
    const d = body[i + 1];
    const simple = { a: 7, b: 8, f: 12, n: 10, r: 13, t: 9, v: 11, "\\": 92, '"': 34, "'": 39, "\n": 10 };
    if (d in simple) { out.push(simple[d]); i += 2; continue; }
    if (d === "x") { out.push(parseInt(body.substr(i + 2, 2), 16) || 0); i += 4; continue; }
    if (d === "z") { i += 2; while (i < body.length && " \t\r\n\f\v".includes(body[i])) i++; continue; }
    if (d === "u" && body[i + 2] === "{") { const e = body.indexOf("}", i + 3); for (const b of utf8(parseInt(body.slice(i + 3, e), 16) || 0)) out.push(b); i = e + 1; continue; }
    if (d >= "0" && d <= "9") { let k = i + 1, s = ""; while (k < body.length && s.length < 3 && /[0-9]/.test(body[k])) s += body[k++]; out.push(parseInt(s, 10) & 0xff); i = k; continue; }
    for (const b of enc.encode(d)) out.push(b); i += 2;
  }
  return Uint8Array.from(out);
}
function strBytes(node) {
  const raw = node.raw;
  if (raw[0] === '"' || raw[0] === "'") return unescapeBytes(raw.slice(1, -1));
  const m = raw.match(/^\[(=*)\[/);
  const lvl = m[1].length;
  let inner = raw.slice(2 + lvl, raw.length - (2 + lvl));
  if (inner[0] === "\n") inner = inner.slice(1);
  return new TextEncoder().encode(inner);
}
function numLit(v) {
  if (!isFinite(v)) throw new Error("non-finite number literal");
  return Number.isInteger(v) && Math.abs(v) < 2 ** 53 ? String(v) : String(v);
}

// Pack an opcode array into bytes (3 per value, little-endian; all values are
// small non-negative ints) so it can be encrypted and only decoded at runtime.
function codeToBytes(arr) {
  const out = new Uint8Array(arr.length * 3);
  for (let i = 0; i < arr.length; i++) {
    const n = arr[i] >>> 0;
    out[i * 3] = n & 0xff; out[i * 3 + 1] = (n >> 8) & 0xff; out[i * 3 + 2] = (n >> 16) & 0xff;
  }
  return out;
}

/* ---------------- compiler ---------------- */

export function compileToVM(src) {
  const ast = luaparse.parse(src, { ranges: false, luaversion: "5.3", comments: false });
  const protos = [];
  const OP = makeOps(); // per-build opcode numbers (shadows the module template)

  function newFunc(parent, vararg) {
    const fs = { parent, index: protos.length + 1, code: [], jmps: [], k: [], kmap: new Map(), up: [], upmap: new Map(), np: 0, vararg, slots: 0, scopes: [new Map()], loops: [] };
    protos.push(null); // Lua P is 1-based; fs.index is the 1-based slot
    return fs;
  }
  const emit = (fs, ...n) => { for (const x of n) fs.code.push(x); };
  const label = () => ({ pos: -1 });
  const mark = (fs, lab) => { lab.pos = fs.code.length + 1; };
  const emitJ = (fs, op, lab) => { fs.code.push(op); fs.jmps.push({ idx: fs.code.length, lab }); fs.code.push(0); };
  const newSlot = (fs) => ++fs.slots;
  const pushScope = (fs) => fs.scopes.push(new Map());
  const popScope = (fs) => fs.scopes.pop();
  const declare = (fs, name) => { const s = newSlot(fs); fs.scopes[fs.scopes.length - 1].set(name, s); return s; };
  function K(fs, kind, val) {
    const key = kind + ":" + (kind === "s" ? [...val].join(",") : val);
    if (fs.kmap.has(key)) return fs.kmap.get(key);
    fs.k.push(kind === "s" ? { s: val } : { n: val });
    const idx = fs.k.length;
    fs.kmap.set(key, idx);
    return idx;
  }
  const Kn = (fs, num) => K(fs, "n", num);
  function Kraw(fs, raw) {
    const key = "r:" + raw;
    if (fs.kmap.has(key)) return fs.kmap.get(key);
    fs.k.push({ r: raw });
    const idx = fs.k.length; fs.kmap.set(key, idx); return idx;
  }

  function resolveLocal(fs, name) {
    for (let i = fs.scopes.length - 1; i >= 0; i--) if (fs.scopes[i].has(name)) return fs.scopes[i].get(name);
    return null;
  }
  function resolveUpval(fs, name) {
    if (fs.upmap.has(name)) return fs.upmap.get(name);
    if (!fs.parent) return null;
    const pl = resolveLocal(fs.parent, name);
    if (pl != null) { fs.up.push([1, pl]); const i = fs.up.length; fs.upmap.set(name, i); return i; }
    const pu = resolveUpval(fs.parent, name);
    if (pu != null) { fs.up.push([0, pu]); const i = fs.up.length; fs.upmap.set(name, i); return i; }
    return null;
  }
  function resolve(fs, name) {
    const l = resolveLocal(fs, name); if (l != null) return { k: "local", i: l };
    const u = resolveUpval(fs, name); if (u != null) return { k: "upval", i: u };
    return { k: "global", name };
  }

  /* ---- expressions (leave exactly one value) ---- */
  function expr(fs, e) {
    switch (e.type) {
      case "NilLiteral": emit(fs, OP.LOADNIL); break;
      case "BooleanLiteral": emit(fs, OP.LOADBOOL, e.value ? 1 : 0); break;
      case "NumericLiteral": emit(fs, OP.LOADK, Kraw(fs, e.raw != null ? String(e.raw).replace(/_/g, "") : numLit(e.value))); break;
      case "StringLiteral": emit(fs, OP.LOADK, K(fs, "s", strBytes(e))); break;
      case "VarargLiteral": if (!fs.vararg) throw new Error("vararg outside vararg function"); emit(fs, OP.VARARGPACK, OP.UNPACK1); break;
      case "Identifier": {
        const r = resolve(fs, e.name);
        if (r.k === "local") emit(fs, OP.GETLOCAL, r.i);
        else if (r.k === "upval") emit(fs, OP.GETUPVAL, r.i);
        else emit(fs, OP.GETGLOBAL, K(fs, "s", new TextEncoder().encode(e.name)));
        break;
      }
      case "BinaryExpression": {
        const c = BIN[e.operator]; if (!c) throw new Error("binop " + e.operator);
        expr(fs, e.left); expr(fs, e.right); emit(fs, OP.BINOP, c); break;
      }
      case "LogicalExpression": {
        expr(fs, e.left); emit(fs, OP.DUP);
        const end = label();
        emitJ(fs, e.operator === "and" ? OP.JMPIFNOT : OP.JMPIF, end);
        emit(fs, OP.POPTOP); expr(fs, e.right); mark(fs, end); break;
      }
      case "UnaryExpression": {
        const c = UN[e.operator]; if (!c) throw new Error("unop " + e.operator);
        expr(fs, e.argument); emit(fs, OP.UNOP, c); break;
      }
      case "MemberExpression":
        if (e.indexer !== ".") throw new Error("member indexer " + e.indexer);
        expr(fs, e.base); emit(fs, OP.LOADK, K(fs, "s", new TextEncoder().encode(e.identifier.name))); emit(fs, OP.GETINDEX); break;
      case "IndexExpression":
        expr(fs, e.base); expr(fs, e.index); emit(fs, OP.GETINDEX); break;
      case "CallExpression": case "TableCallExpression": case "StringCallExpression":
        callExpr(fs, e); emit(fs, OP.UNPACK1); break;
      case "FunctionDeclaration": emit(fs, OP.CLOSURE, compileFunction(fs, e, false)); break;
      case "TableConstructorExpression": tableExpr(fs, e); break;
      default: throw new Error("expr " + e.type);
    }
  }

  function callArgsNode(e) {
    if (e.type === "StringCallExpression") return [e.argument];
    if (e.type === "TableCallExpression") return [e.arguments];
    return e.arguments;
  }

  // leaves a result-pack on the stack
  function callExpr(fs, e) {
    const isMethod = e.base.type === "MemberExpression" && e.base.indexer === ":";
    if (isMethod) {
      const t = newSlot(fs);
      expr(fs, e.base.base); emit(fs, OP.SETLOCAL, t);
      emit(fs, OP.GETLOCAL, t); emit(fs, OP.LOADK, K(fs, "s", new TextEncoder().encode(e.base.identifier.name))); emit(fs, OP.GETINDEX); // fn
      emit(fs, OP.NEWACC); emit(fs, OP.GETLOCAL, t); emit(fs, OP.ACCPUSH); // self as first arg
      appendArgs(fs, callArgsNode(e));
      emit(fs, OP.CALL);
    } else {
      expr(fs, e.base);
      emit(fs, OP.NEWACC);
      appendArgs(fs, callArgsNode(e));
      emit(fs, OP.CALL);
    }
  }

  // acc is on top of stack; append each arg, spreading a trailing call/vararg
  function appendArgs(fs, list) {
    for (let i = 0; i < list.length; i++) {
      const a = list[i], last = i === list.length - 1;
      if (last && (a.type === "CallExpression" || a.type === "TableCallExpression" || a.type === "StringCallExpression")) { callExpr(fs, a); emit(fs, OP.ACCEXTEND); }
      else if (last && a.type === "VarargLiteral") { if (!fs.vararg) throw new Error("vararg"); emit(fs, OP.VARARGPACK); emit(fs, OP.ACCEXTEND); }
      else { expr(fs, a); emit(fs, OP.ACCPUSH); }
    }
  }

  // build an accumulator table holding the full value list
  function listAcc(fs, list) {
    emit(fs, OP.NEWACC);
    appendArgs(fs, list || []);
  }

  function tableExpr(fs, e) {
    emit(fs, OP.NEWTABLE);
    let arrIdx = 0;
    const fields = e.fields;
    for (let i = 0; i < fields.length; i++) {
      const f = fields[i], last = i === fields.length - 1;
      if (f.type === "TableKey") { expr(fs, f.key); expr(fs, f.value); emit(fs, OP.SETFIELDKEEP); }
      else if (f.type === "TableKeyString") { emit(fs, OP.LOADK, K(fs, "s", new TextEncoder().encode(f.key.name))); expr(fs, f.value); emit(fs, OP.SETFIELDKEEP); }
      else { // TableValue
        const v = f.value;
        if (last && (v.type === "CallExpression" || v.type === "TableCallExpression" || v.type === "StringCallExpression")) { callExpr(fs, v); emit(fs, OP.SETLISTMULTI, arrIdx); }
        else if (last && v.type === "VarargLiteral") { if (!fs.vararg) throw new Error("vararg"); emit(fs, OP.VARARGPACK); emit(fs, OP.SETLISTMULTI, arrIdx); }
        else { arrIdx++; emit(fs, OP.LOADK, Kn(fs, arrIdx)); expr(fs, v); emit(fs, OP.SETFIELDKEEP); }
      }
    }
  }

  // store the value currently produced by `valueEmitter` into an lvalue
  function assignTo(fs, target, valueEmitter) {
    if (target.type === "Identifier") {
      const r = resolve(fs, target.name);
      valueEmitter();
      if (r.k === "local") emit(fs, OP.SETLOCAL, r.i);
      else if (r.k === "upval") emit(fs, OP.SETUPVAL, r.i);
      else emit(fs, OP.SETGLOBAL, K(fs, "s", new TextEncoder().encode(target.name)));
    } else if (target.type === "MemberExpression") {
      if (target.indexer !== ".") throw new Error("assign indexer " + target.indexer);
      expr(fs, target.base); emit(fs, OP.LOADK, K(fs, "s", new TextEncoder().encode(target.identifier.name))); valueEmitter(); emit(fs, OP.SETINDEX);
    } else if (target.type === "IndexExpression") {
      expr(fs, target.base); expr(fs, target.index); valueEmitter(); emit(fs, OP.SETINDEX);
    } else throw new Error("assign target " + target.type);
  }

  /* ---- statements ---- */
  function block(fs, stmts) { for (const s of stmts) stmt(fs, s); }
  function body(fs, stmts) { pushScope(fs); block(fs, stmts); popScope(fs); }

  function stmt(fs, s) {
    switch (s.type) {
      case "LocalStatement": {
        listAcc(fs, s.init || []);
        const acc = newSlot(fs); emit(fs, OP.SETLOCAL, acc); // hold the value list
        for (let i = 0; i < s.variables.length; i++) {
          const slot = declare(fs, s.variables[i].name);
          emit(fs, OP.GETLOCAL, acc); emit(fs, OP.LOADK, Kn(fs, i + 1)); emit(fs, OP.GETINDEX); emit(fs, OP.SETLOCAL, slot);
        }
        break;
      }
      case "AssignmentStatement": {
        listAcc(fs, s.init);
        const acc = newSlot(fs); emit(fs, OP.SETLOCAL, acc);
        for (let i = 0; i < s.variables.length; i++) {
          assignTo(fs, s.variables[i], () => { emit(fs, OP.GETLOCAL, acc); emit(fs, OP.LOADK, Kn(fs, i + 1)); emit(fs, OP.GETINDEX); });
        }
        break;
      }
      case "CallStatement": callExpr(fs, s.expression); emit(fs, OP.POPTOP); break;
      case "ReturnStatement": listAcc(fs, s.arguments || []); emit(fs, OP.RETURNACC); break;
      case "FunctionDeclaration": {
        if (s.isLocal) { const slot = declare(fs, s.identifier.name); emit(fs, OP.CLOSURE, compileFunction(fs, s, false)); emit(fs, OP.SETLOCAL, slot); }
        else {
          const isMethod = s.identifier.type === "MemberExpression" && s.identifier.indexer === ":";
          const idx = compileFunction(fs, s, isMethod);
          const tmp = newSlot(fs); emit(fs, OP.CLOSURE, idx); emit(fs, OP.SETLOCAL, tmp);
          const target = s.identifier.type === "MemberExpression"
            ? { type: "MemberExpression", indexer: ".", base: s.identifier.base, identifier: s.identifier.identifier }
            : s.identifier;
          assignTo(fs, target, () => emit(fs, OP.GETLOCAL, tmp));
        }
        break;
      }
      case "IfStatement": {
        const end = label();
        for (const cl of s.clauses) {
          if (cl.type === "ElseClause") { body(fs, cl.body); }
          else {
            expr(fs, cl.condition);
            const next = label();
            emitJ(fs, OP.JMPIFNOT, next);
            body(fs, cl.body);
            emitJ(fs, OP.JMP, end);
            mark(fs, next);
          }
        }
        mark(fs, end);
        break;
      }
      case "WhileStatement": {
        const start = label(), end = label();
        mark(fs, start);
        expr(fs, s.condition); emitJ(fs, OP.JMPIFNOT, end);
        fs.loops.push(end); body(fs, s.body); fs.loops.pop();
        emitJ(fs, OP.JMP, start); mark(fs, end);
        break;
      }
      case "DoStatement": body(fs, s.body); break;
      case "RepeatStatement": {
        const start = label(), end = label();
        mark(fs, start);
        pushScope(fs);
        fs.loops.push(end); block(fs, s.body); fs.loops.pop();
        expr(fs, s.condition); emitJ(fs, OP.JMPIFNOT, start); // loop while condition false
        popScope(fs);
        mark(fs, end);
        break;
      }
      case "BreakStatement": if (!fs.loops.length) throw new Error("break outside loop"); emitJ(fs, OP.JMP, fs.loops[fs.loops.length - 1]); break;
      case "ForNumericStatement": forNumeric(fs, s); break;
      case "ForGenericStatement": forGeneric(fs, s); break;
      default: throw new Error("stmt " + s.type);
    }
  }

  function forNumeric(fs, s) {
    const iv = newSlot(fs), lim = newSlot(fs), stp = newSlot(fs);
    expr(fs, s.start); emit(fs, OP.SETLOCAL, iv);
    expr(fs, s.end); emit(fs, OP.SETLOCAL, lim);
    if (s.step) expr(fs, s.step); else emit(fs, OP.LOADK, Kn(fs, 1));
    emit(fs, OP.SETLOCAL, stp);
    const start = label(), neg = label(), test = label(), end = label();
    mark(fs, start);
    // stp > 0 ?
    emit(fs, OP.GETLOCAL, stp); emit(fs, OP.LOADK, Kn(fs, 0)); emit(fs, OP.BINOP, BIN[">"]);
    emitJ(fs, OP.JMPIFNOT, neg);
    emit(fs, OP.GETLOCAL, iv); emit(fs, OP.GETLOCAL, lim); emit(fs, OP.BINOP, BIN["<="]);
    emitJ(fs, OP.JMP, test);
    mark(fs, neg);
    emit(fs, OP.GETLOCAL, iv); emit(fs, OP.GETLOCAL, lim); emit(fs, OP.BINOP, BIN[">="]);
    mark(fs, test);
    emitJ(fs, OP.JMPIFNOT, end);
    pushScope(fs);
    const vv = declare(fs, s.variable.name);
    emit(fs, OP.GETLOCAL, iv); emit(fs, OP.SETLOCAL, vv);
    fs.loops.push(end); block(fs, s.body); fs.loops.pop();
    popScope(fs);
    emit(fs, OP.GETLOCAL, iv); emit(fs, OP.GETLOCAL, stp); emit(fs, OP.BINOP, BIN["+"]); emit(fs, OP.SETLOCAL, iv);
    emitJ(fs, OP.JMP, start);
    mark(fs, end);
  }

  function forGeneric(fs, s) {
    const f = newSlot(fs), st = newSlot(fs), ctrl = newSlot(fs), pk = newSlot(fs);
    listAcc(fs, s.iterators);
    const acc = newSlot(fs); emit(fs, OP.SETLOCAL, acc);
    emit(fs, OP.GETLOCAL, acc); emit(fs, OP.LOADK, Kn(fs, 1)); emit(fs, OP.GETINDEX); emit(fs, OP.SETLOCAL, f);
    emit(fs, OP.GETLOCAL, acc); emit(fs, OP.LOADK, Kn(fs, 2)); emit(fs, OP.GETINDEX); emit(fs, OP.SETLOCAL, st);
    emit(fs, OP.GETLOCAL, acc); emit(fs, OP.LOADK, Kn(fs, 3)); emit(fs, OP.GETINDEX); emit(fs, OP.SETLOCAL, ctrl);
    const start = label(), end = label();
    mark(fs, start);
    // pk = f(st, ctrl)
    emit(fs, OP.GETLOCAL, f); emit(fs, OP.NEWACC); emit(fs, OP.GETLOCAL, st); emit(fs, OP.ACCPUSH); emit(fs, OP.GETLOCAL, ctrl); emit(fs, OP.ACCPUSH); emit(fs, OP.CALL);
    emit(fs, OP.SETLOCAL, pk);
    // ctrl = pk[1]; if ctrl == nil then end
    emit(fs, OP.GETLOCAL, pk); emit(fs, OP.LOADK, Kn(fs, 1)); emit(fs, OP.GETINDEX); emit(fs, OP.SETLOCAL, ctrl);
    emit(fs, OP.GETLOCAL, ctrl); emit(fs, OP.LOADNIL); emit(fs, OP.BINOP, BIN["=="]); emitJ(fs, OP.JMPIF, end);
    pushScope(fs);
    for (let i = 0; i < s.variables.length; i++) {
      const slot = declare(fs, s.variables[i].name);
      emit(fs, OP.GETLOCAL, pk); emit(fs, OP.LOADK, Kn(fs, i + 1)); emit(fs, OP.GETINDEX); emit(fs, OP.SETLOCAL, slot);
    }
    fs.loops.push(end); block(fs, s.body); fs.loops.pop();
    popScope(fs);
    emitJ(fs, OP.JMP, start);
    mark(fs, end);
  }

  function compileFunction(parent, node, isMethod) {
    const vararg = node.parameters.some((p) => p.type === "VarargLiteral");
    const fs = newFunc(parent, vararg);
    if (isMethod) declare(fs, "self");
    for (const p of node.parameters) if (p.type === "Identifier") declare(fs, p.name);
    fs.np = fs.slots; // params occupy the first slots
    for (let i = 1; i <= fs.np; i++) { emit(fs, OP.GETVARARGN, i); emit(fs, OP.SETLOCAL, i); }
    block(fs, node.body);
    emit(fs, OP.RETURN0);
    finalize(fs);
    return fs.index;
  }

  function finalize(fs) {
    for (const j of fs.jmps) fs.code[j.idx] = j.lab.pos;
    protos[fs.index - 1] = { c: fs.code, k: fs.k, u: fs.up, np: fs.np, s: fs.slots, v: fs.vararg };
  }

  const main = newFunc(null, true);
  main.np = 0;
  block(main, ast.body);
  emit(main, OP.RETURN0);
  finalize(main);

  return buildProgram(protos, main.index, OP);
}

/* ---------------- serialize + runtime ---------------- */

function buildProgram(protos, mainIndex, OP) {
  const used = new Set();
  const decName = uname(used);
  const dc = uname(used); // decodes an encrypted opcode array
  const N = {};
  for (const key of ["run", "P", "ENV", "tp", "tu", "push", "pop", "S", "sp", "L", "K", "pr", "ip", "C", "U", "VA", "op", "pi"]) N[key] = uname(used);
  const { run, P, ENV, tp, tu, push, pop, S, sp, L, K, pr, ip, C, U, VA, op, pi } = N;

  const serK = (k) => {
    if ("r" in k) return k.r;
    if ("n" in k) return numLit(k.n);
    const seed = rnd32();
    return `${decName}("${cipherB64(k.s, seed)}",${seed})`;
  };
  const serProto = (p) => {
    const cseed = rnd32();
    const cblob = cipherB64(codeToBytes(p.c), cseed); // the actual program logic, encrypted
    return `{c=${dc}("${cblob}",${cseed}),k={${p.k.map(serK).join(",")}},u={${p.u.map((d) => `{${d[0]},${d[1]}}`).join(",")}},np=${p.np},s=${p.s},v=${p.v ? "true" : "false"}}`;
  };

  // One handler body per opcode, built from the randomized VM names.
  const H = {
    LOADK: `${push}(${K}[${C}[${ip}]]) ${ip}=${ip}+1`,
    LOADBOOL: `${push}(${C}[${ip}]==1) ${ip}=${ip}+1`,
    LOADNIL: `${push}(nil)`,
    GETLOCAL: `${push}(${L}[${C}[${ip}]][1]) ${ip}=${ip}+1`,
    SETLOCAL: `${L}[${C}[${ip}]][1]=${pop}() ${ip}=${ip}+1`,
    GETGLOBAL: `${push}(${ENV}[${K}[${C}[${ip}]]]) ${ip}=${ip}+1`,
    SETGLOBAL: `${ENV}[${K}[${C}[${ip}]]]=${pop}() ${ip}=${ip}+1`,
    GETUPVAL: `${push}(${U}[${C}[${ip}]][1]) ${ip}=${ip}+1`,
    SETUPVAL: `${U}[${C}[${ip}]][1]=${pop}() ${ip}=${ip}+1`,
    NEWTABLE: `${push}({})`,
    GETINDEX: `local k=${pop}() local t=${pop}() ${push}(t[k])`,
    SETINDEX: `local v=${pop}() local k=${pop}() local t=${pop}() t[k]=v`,
    BINOP: `local c=${C}[${ip}] ${ip}=${ip}+1 local b=${pop}() local a=${pop}() if c==1 then ${push}(a+b) elseif c==2 then ${push}(a-b) elseif c==3 then ${push}(a*b) elseif c==4 then ${push}(a/b) elseif c==5 then ${push}(a%b) elseif c==6 then ${push}(a^b) elseif c==7 then ${push}(a..b) elseif c==8 then ${push}(a==b) elseif c==9 then ${push}(a~=b) elseif c==10 then ${push}(a<b) elseif c==11 then ${push}(a<=b) elseif c==12 then ${push}(a>b) else ${push}(a>=b) end`,
    UNOP: `local c=${C}[${ip}] ${ip}=${ip}+1 local a=${pop}() if c==1 then ${push}(-a) elseif c==2 then ${push}(not a) else ${push}(#a) end`,
    NEWACC: `${push}({n=0})`,
    ACCPUSH: `local v=${pop}() local acc=${S}[${sp}] acc.n=acc.n+1 acc[acc.n]=v`,
    CALL: `local acc=${pop}() local fn=${pop}() ${push}(${tp}(fn(${tu}(acc,1,acc.n))))`,
    RETURN0: `return`,
    RETURNACC: `local acc=${pop}() return ${tu}(acc,1,acc.n)`,
    JMP: `${ip}=${C}[${ip}]`,
    JMPIFNOT: `local c=${pop}() if not c then ${ip}=${C}[${ip}] else ${ip}=${ip}+1 end`,
    JMPIF: `local c=${pop}() if c then ${ip}=${C}[${ip}] else ${ip}=${ip}+1 end`,
    POPTOP: `${pop}()`,
    CLOSURE: `local pidx=${C}[${ip}] ${ip}=${ip}+1 local p2=${P}[pidx] local U2={} for i=1,#p2.u do local d=p2.u[i] if d[1]==1 then U2[i]=${L}[d[2]] else U2[i]=${U}[d[2]] end end ${push}(function(...) return ${run}(pidx,U2,${tp}(...)) end)`,
    VARARGPACK: `local t={n=0} for i=${pr}.np+1,${VA}.n do t.n=t.n+1 t[t.n]=${VA}[i] end ${push}(t)`,
    UNPACK1: `local p=${pop}() ${push}(p[1])`,
    ACCEXTEND: `local p=${pop}() local acc=${S}[${sp}] for i=1,p.n do acc.n=acc.n+1 acc[acc.n]=p[i] end`,
    ACCGET: `local acc=${S}[${sp}] ${push}(acc[${C}[${ip}]]) ${ip}=${ip}+1`,
    SETFIELDKEEP: `local v=${pop}() local k=${pop}() local t=${S}[${sp}] t[k]=v`,
    SETLISTMULTI: `local p=${pop}() local t=${S}[${sp}] local base=${C}[${ip}] ${ip}=${ip}+1 for i=1,p.n do t[base+i]=p[i] end`,
    GETVARARGN: `${push}(${VA}[${C}[${ip}]]) ${ip}=${ip}+1`,
    DUP: `${push}(${S}[${sp}])`,
  };

  const dispatch = shuffle(Object.keys(H))
    .map((name, i) => `${i === 0 ? "if" : "elseif"} ${op}==${OP[name]} then ${H[name]}`)
    .join("\n") + "\nend";

  return `${decLua(decName)}
local function ${dc}(d,s) local b=${decName}(d,s) local t={} for i=1,#b,3 do t[#t+1]=b:byte(i)+b:byte(i+1)*256+b:byte(i+2)*65536 end return t end
local ${P}={${protos.map(serProto).join(",")}}
local ${ENV}=(getfenv and getfenv()) or _ENV
local ${tp},${tu}=table.pack,table.unpack
local ${run}
${run}=function(${pi},${U},${VA})
local ${pr}=${P}[${pi}] local ${C},${K}=${pr}.c,${pr}.k
local ${L}={} for i=1,${pr}.s do ${L}[i]={} end
local ${S},${sp}={},0
local function ${push}(v) ${sp}=${sp}+1 ${S}[${sp}]=v end
local function ${pop}() local v=${S}[${sp}] ${S}[${sp}]=nil ${sp}=${sp}-1 return v end
local ${ip}=1
while true do
local ${op}=${C}[${ip}] ${ip}=${ip}+1
${dispatch}
end
end
return ${run}(${mainIndex},{},{n=0})`;
}
