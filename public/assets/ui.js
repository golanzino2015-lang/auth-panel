/* Shared helpers for every page. */

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const LOGO = `<span class="logo-mark" aria-hidden="true">◆</span>`;

function toast(msg) {
  let t = $("#toast");
  if (!t) { t = document.createElement("div"); t.id = "toast"; document.body.appendChild(t); }
  t.textContent = msg; t.classList.add("show");
  clearTimeout(toast._t); toast._t = setTimeout(() => t.classList.remove("show"), 1800);
}

async function copy(text, msg = "Copied") {
  try { await navigator.clipboard.writeText(text); }
  catch {
    const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta);
    ta.select(); document.execCommand("copy"); ta.remove();
  }
  toast(msg);
}

function fmtNum(n) {
  n = Number(n) || 0;
  if (n >= 1e6) return (n / 1e6).toFixed(n >= 1e7 ? 0 : 1) + "M";
  if (n >= 1e4) return (n / 1e3).toFixed(n >= 1e5 ? 0 : 1) + "K";
  return n.toLocaleString();
}
function fmtDate(ms) {
  return ms ? new Date(ms).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }) : "—";
}
function ago(ms) {
  if (!ms) return "never";
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 60) return s + "s ago";
  if (s < 3600) return Math.floor(s / 60) + "m ago";
  if (s < 86400) return Math.floor(s / 3600) + "h ago";
  return Math.floor(s / 86400) + "d ago";
}
function left(ms) {
  const d = ms - Date.now();
  if (d <= 0) return "expired";
  const days = Math.floor(d / 864e5), h = Math.floor((d % 864e5) / 36e5), m = Math.floor((d % 36e5) / 6e4);
  return days ? `${days}d ${h}h` : h ? `${h}h ${m}m` : `${m}m`;
}

/**
 * Area chart into an <svg>. series = [{day, ok, fail}]
 * Draws "ok" as a filled line and "fail" as a dashed line.
 */
function drawChart(svg, series, { height = 220 } = {}) {
  const W = 760, H = height, pad = { t: 14, r: 8, b: 8, l: 8 };
  const max = Math.max(4, ...series.map((d) => d.ok + d.fail)) * 1.15;
  const x = (i) => pad.l + (i / Math.max(1, series.length - 1)) * (W - pad.l - pad.r);
  const y = (v) => pad.t + (1 - v / max) * (H - pad.t - pad.b);
  const smooth = (pts) => pts.reduce((d, [px, py], i, a) => {
    if (!i) return `M${px},${py}`;
    const [qx, qy] = a[i - 1], cx = (qx + px) / 2;
    return d + ` C${cx},${qy} ${cx},${py} ${px},${py}`;
  }, "");
  const okPts = series.map((d, i) => [x(i), y(d.ok)]);
  const failPts = series.map((d, i) => [x(i), y(d.fail)]);
  const line = smooth(okPts);
  const id = "g" + Math.random().toString(36).slice(2, 7);
  const grid = [0.25, 0.5, 0.75].map((f) => `<line x1="0" x2="${W}" y1="${pad.t + f * (H - pad.t - pad.b)}" y2="${pad.t + f * (H - pad.t - pad.b)}" stroke="#232837" stroke-dasharray="2 4"/>`).join("");
  const last = okPts[okPts.length - 1];
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  svg.innerHTML = `
    <defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="#7c5cff" stop-opacity=".35"/><stop offset="1" stop-color="#7c5cff" stop-opacity="0"/>
    </linearGradient></defs>
    ${grid}
    <path d="${line} L${x(series.length - 1)},${H} L${x(0)},${H} Z" fill="url(#${id})"/>
    <path d="${smooth(failPts)}" fill="none" stroke="#ff5c7a" stroke-opacity=".7" stroke-width="1.25" stroke-dasharray="3 4" vector-effect="non-scaling-stroke"/>
    <path d="${line}" fill="none" stroke="#9d85ff" stroke-width="2" vector-effect="non-scaling-stroke"/>
  `;
}

function chartAxis(el, series) {
  const pick = [0, 4, 8, 12, series.length - 1];
  el.innerHTML = pick.map((i, n) => `<span>${n === pick.length - 1 ? "Today"
    : new Date(series[i].day).toLocaleDateString([], { month: "short", day: "2-digit", timeZone: "UTC" })}</span>`).join("");
}
