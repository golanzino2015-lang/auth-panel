/* The Wall-1 client loader (served at /v1/l). Kept in its own module so it can
 * be unit-tested and run through the obfuscator before serving. No Worker-only
 * imports here, so it loads under plain Node for tests. */

/** Any JS string -> safe double-quoted Lua string literal. */
export function luaStr(s) {
  let out = '"';
  for (const ch of new TextEncoder().encode(String(s))) {
    if (ch === 0x22) out += '\\"';
    else if (ch === 0x5c) out += "\\\\";
    else if (ch >= 0x20 && ch < 0x7f) out += String.fromCharCode(ch);
    else out += "\\" + String(ch).padStart(3, "0");
  }
  return out + '"';
}

// base64 + xorshift32 decoder in Luau, used by the loader to decode the /v1/s payload.
export const LUA_DECODER = `local function dec(data, seed)
    local b = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    local lut = {}
    for i = 1, 64 do lut[b:sub(i, i)] = i - 1 end
    local bytes, acc, bits = {}, 0, 0
    for i = 1, #data do
        local c = data:sub(i, i)
        if c == "=" then break end
        local v = lut[c]
        if v then
            acc = acc * 64 + v; bits = bits + 6
            if bits >= 8 then
                bits = bits - 8
                bytes[#bytes + 1] = math.floor(acc / (2 ^ bits)) % 256
                acc = acc % (2 ^ bits)
            end
        end
    end
    local x = seed % 4294967296
    if x == 0 then x = 2654435769 end
    local out = {}
    for i = 1, #bytes do
        x = bit32.bxor(x, bit32.lshift(x, 13))
        x = bit32.bxor(x, bit32.rshift(x, 17))
        x = bit32.bxor(x, bit32.lshift(x, 5))
        out[i] = string.char(bit32.bxor(bytes[i], bit32.band(x, 255)))
    end
    return table.concat(out)
end`;

// The real loader. It reads script_key + HWID, runs an anti-tamper check, calls
// /v1/a to verify, then /v1/s to fetch and decode the (also-obfuscated) script.
export function loaderInner(origin, session) {
  return `local BASE = ${luaStr(origin)}
local SS = ${luaStr(session)}

local function notify(m)
    warn("[Auth] " .. tostring(m))
    pcall(function()
        game:GetService("StarterGui"):SetCore("SendNotification", { Title = "Auth", Text = tostring(m), Duration = 8 })
    end)
end

local genv = (getgenv and getgenv()) or _G
local key = script_key or genv.script_key or _G.script_key
key = type(key) == "string" and key:gsub("%s", "") or ""

local hwid
pcall(function() if gethwid then hwid = gethwid() end end)
if not hwid or hwid == "" then
    pcall(function() hwid = game:GetService("RbxAnalyticsService"):GetClientId() end)
end
hwid = tostring(hwid or "")

local ex = ""
pcall(function() if identifyexecutor then ex = tostring((identifyexecutor())) end end)

local tamper = "0"
pcall(function()
    if iscclosure then
        if (not iscclosure(loadstring)) or (not iscclosure(game.HttpGet)) then tamper = "1" end
    end
end)

local Http = game:GetService("HttpService")
local function e(s) return Http:UrlEncode(s) end

local ok1, r1 = pcall(function()
    return game:HttpGet(BASE .. "/v1/a?s=" .. SS .. "&k=" .. e(key) .. "&h=" .. e(hwid) .. "&x=" .. e(ex) .. "&t=" .. tamper)
end)
if not ok1 or type(r1) ~= "string" then return notify("Could not reach the key server.") end
local head = r1:sub(1, 1)
if head == "!" then return notify(r1:sub(2)) end
if head ~= "#" then return notify("Unexpected server response.") end

local rest = r1:sub(2)
local bar = rest:find("|", 1, true)
if not bar then return notify("Bad server response.") end
local ticket = rest:sub(1, bar - 1)
local seed = tonumber(rest:sub(bar + 1), 16) or 0

local ok2, r2 = pcall(function() return game:HttpGet(BASE .. "/v1/s/" .. ticket) end)
if not ok2 or type(r2) ~= "string" then return notify("Could not reach the key server.") end
if r2:sub(1, 1) == "!" then return notify(r2:sub(2)) end

${LUA_DECODER}

local fn, err = loadstring(dec(r2, seed))
if not fn then return notify("Script failed to load.") end
return fn(...)`;
}

// Plain error chunk (used when the script id is unknown — nothing secret to protect).
export function errorLua(msg) {
  return `warn("[Auth] " .. ${luaStr(msg)})
pcall(function()
    game:GetService("StarterGui"):SetCore("SendNotification", { Title = "Auth", Text = ${luaStr(msg)}, Duration = 8 })
end)`;
}
