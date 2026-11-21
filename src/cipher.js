/* Shared cipher helpers for the obfuscator and the bytecode VM.
 * xorshift32 keystream over bytes, base64-encoded. The Lua `dec` below is the
 * exact inverse and must stay in lockstep with cipherB64. */

export const rnd32 = () => (crypto.getRandomValues(new Uint32Array(1))[0] >>> 0);

export function cipherB64(bytes, seed) {
  let x = (seed >>> 0) || 0x9e3779b9;
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    x = (x ^ (x << 13)) >>> 0;
    x = (x ^ (x >>> 17)) >>> 0;
    x = (x ^ (x << 5)) >>> 0;
    out[i] = bytes[i] ^ (x & 0xff);
  }
  let bin = "";
  for (let i = 0; i < out.length; i += 0x8000) bin += String.fromCharCode.apply(null, out.subarray(i, i + 0x8000));
  return btoa(bin);
}

export function strBytes(s) { return new TextEncoder().encode(s); }

// The Lua-side base64 + xorshift decoder. `name` lets each build rename it.
export function decLua(name) {
  return `local function ${name}(d,s)
local b="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local L={} for i=1,64 do L[b:sub(i,i)]=i-1 end
local by,a,n2={},0,0
for i=1,#d do local c=d:sub(i,i) if c=="=" then break end local v=L[c] if v then a=a*64+v n2=n2+6 if n2>=8 then n2=n2-8 by[#by+1]=bit32.band(bit32.rshift(a,n2),255) a=bit32.band(a,bit32.lshift(1,n2)-1) end end end
local x=s%4294967296 if x==0 then x=2654435769 end
local o={}
for i=1,#by do x=bit32.bxor(x,bit32.lshift(x,13)) x=bit32.bxor(x,bit32.rshift(x,17)) x=bit32.bxor(x,bit32.lshift(x,5)) o[i]=string.char(bit32.bxor(by[i],bit32.band(x,255))) end
return table.concat(o)
end`;
}
