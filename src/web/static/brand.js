// Saga's moving brand: a light that sweeps along the wordmark's orbit, and a tab icon where a small
// moon circles the logo's "S" on the same tilted ring, passing behind it and back in front.
// Browsers don't animate SVG favicons, so the icon is drawn on a canvas and swapped a few times a second.
(() => {
  const still = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---- wordmark: SAGA with a black hole's accretion disk around it ----
  // Vector letters in the logo's style, drawn in currentColor. The disk is a tilted ring: its far half
  // is drawn behind the word and its near half in front, with streaks of light circling it and a lensed
  // glow behind the letters. Same 1363×340 box as the old PNG, so every .logo-mark keeps its size.
  const LETTERS = `
    <path class="bh-s" fill="none" stroke="currentColor" stroke-width="54" stroke-linejoin="round"
      d="M266 71H115C52 71 50 144 110 154L226 186C286 196 284 269 221 269H70"/>
    <path d="M265 44H306L265 98ZM71 296H30L71 242Z"/>
    <path d="M330 296L442 44H500L612 296H550L471 118L392 296Z"/>
    <path d="M419 200H523L541 244H401Z"/>
    <path fill="none" stroke="currentColor" stroke-width="54" stroke-linejoin="round"
      d="M852 71H722C670 71 667 90 667 124V216C667 250 670 269 722 269H846C868 269 873 262 873 240V181H776"/>
    <path d="M851 44H902L851 98Z"/>
    <path d="M924 296L1040 44H1100L1216 296H1154L1070 114L986 296Z"/>`;
  // Half-ellipses of the disk around (682,170), tilted like the old logo's ring: the far half goes over
  // the top (behind the word), the near half under the bottom (in front of it).
  const TILT = -9 * Math.PI / 180;
  const arc = (rx, ry, far) => {
    const px = rx * Math.cos(TILT), py = rx * Math.sin(TILT), r = n => Math.round(n * 10) / 10;
    const [a, b] = far ? [[682 + px, 170 + py], [682 - px, 170 - py]] : [[682 - px, 170 - py], [682 + px, 170 + py]];
    return `M${r(a[0])} ${r(a[1])}A${rx} ${ry} -9 0 0 ${r(b[0])} ${r(b[1])}`;
  };
  let uid = 0;
  const logoSvg = () => {
    const id = "bh" + ++uid;
    const half = far => `<g class="${far ? "bh-far" : "bh-near"}">
        <path d="${arc(668, 104, far)}" class="bh-glow" filter="url(#${id}b)"/>
        <path d="${arc(700, 116, far)}" class="bh-band" stroke="url(#${id}d)"/>
        <path d="${arc(668, 102, far)}" class="bh-disk" stroke="url(#${id}d)"/>
        <path d="${arc(636, 90, far)}" class="bh-inner"/>
        <path d="${arc(668, 102, far)}" class="bh-flow a"/><path d="${arc(700, 114, far)}" class="bh-flow b"/>
        <path d="${arc(640, 92, far)}" class="bh-flow c"/></g>`;
    return `<svg class="bh" viewBox="0 0 1363 340" aria-hidden="true" focusable="false">
      <defs>
        <linearGradient id="${id}d" x1="0" x2="1">
          <stop offset="0" stop-color="var(--bh-disk)" stop-opacity="0"/><stop offset=".12" stop-color="var(--bh-hot)"/>
          <stop offset=".45" stop-color="var(--bh-disk)"/><stop offset=".9" stop-color="var(--bh-disk)" stop-opacity=".45"/>
          <stop offset="1" stop-color="var(--bh-disk)" stop-opacity="0"/></linearGradient>
        <radialGradient id="${id}h"><stop offset="0" stop-color="var(--bh-disk)" stop-opacity=".26"/>
          <stop offset=".6" stop-color="var(--bh-disk)" stop-opacity=".08"/><stop offset="1" stop-color="var(--bh-disk)" stop-opacity="0"/></radialGradient>
        <filter id="${id}b" x="-10%" y="-90%" width="120%" height="280%"><feGaussianBlur stdDeviation="10"/></filter>
        <filter id="${id}s" x="-5%" y="-40%" width="110%" height="180%"><feGaussianBlur stdDeviation="3"/></filter>
      </defs>
      <ellipse class="bh-halo" cx="682" cy="170" rx="600" ry="165" fill="url(#${id}h)"/>
      <g class="bh-lens"><path d="M112 180A570 162 0 0 1 1252 180" filter="url(#${id}s)"/><path d="M112 180A570 162 0 0 1 1252 180"/></g>
      ${half(true)}
      <g class="bh-word" fill="currentColor">${LETTERS}</g>
      ${half(false)}
    </svg>`;
  };
  const style = document.createElement("style");
  style.textContent = `
.logo-mark.bh-on { background: none !important; -webkit-mask: none !important; mask: none !important; position: relative; }
.logo-mark .bh { position: absolute; inset: 0; width: 100%; height: 100%; overflow: visible; }
.bh { --bh-disk: var(--a-saga, #3FB5AC); --bh-hot: #E6FFFA; }
.bh-far path, .bh-near path, .bh-lens path { fill: none; stroke-linecap: round; }
.bh .bh-glow { stroke: var(--bh-disk); stroke-width: 34; opacity: .38; }
.bh .bh-band { stroke-width: 20; opacity: .22; }
.bh .bh-disk { stroke-width: 8; }
.bh .bh-inner { stroke: var(--bh-hot); stroke-width: 2.4; opacity: .9; }
.bh .bh-far { opacity: .5; }
.bh .bh-lens path { stroke: var(--bh-disk); stroke-width: 3; opacity: .35; }
.bh .bh-lens path + path { stroke: var(--bh-hot); stroke-width: 1.4; opacity: .55; }
.bh .bh-flow { stroke: var(--bh-hot); stroke-width: 3.4; stroke-dasharray: 70 420 18 330 140 620; animation: bh-flow-a 4.8s linear infinite; }
.bh .bh-flow.b { stroke-width: 2; stroke-dasharray: 26 260 90 510 10 380; animation: bh-flow-b 7s linear infinite; opacity: .75; }
.bh .bh-flow.c { stroke-width: 2.6; stroke-dasharray: 44 300 8 220 60 480; animation: bh-flow-c 3.4s linear infinite; }
.bh .bh-halo { animation: bh-breathe 6s ease-in-out infinite; transform-origin: 682px 170px; }
.bh .bh-lens { animation: bh-lens 6s ease-in-out infinite; }
@keyframes bh-flow-a { to { stroke-dashoffset: -1598; } }
@keyframes bh-flow-b { to { stroke-dashoffset: -1276; } }
@keyframes bh-flow-c { to { stroke-dashoffset: -1112; } }
@keyframes bh-breathe { 50% { opacity: .6; transform: scale(1.05); } }
@keyframes bh-lens { 50% { opacity: .55; } }
.brand:hover .bh .bh-flow, .wordmark:hover .bh .bh-flow { animation-duration: 1.6s; }
.giant .logo-mark.bh-on { color: var(--faint); }
@media (prefers-color-scheme: light) { :root:not([data-theme="dark"]) .bh { --bh-hot: #FFFFFF; } }
:root[data-theme="light"] .bh { --bh-hot: #FFFFFF; }
@media (prefers-reduced-motion: reduce) { .bh .bh-flow, .bh .bh-halo, .bh .bh-lens { animation: none; } }`;
  document.head.appendChild(style);
  const paint = root => root.querySelectorAll(".logo-mark:not(.bh-on)").forEach(el => {
    el.classList.add("bh-on");
    el.innerHTML = logoSvg();
  });
  paint(document);
  new MutationObserver(() => paint(document)).observe(document.body || document.documentElement, {childList: true, subtree: true});

  // ---- tab icon ----
  const N = 64, link = document.querySelector('link[rel="icon"]') || document.head.appendChild(Object.assign(document.createElement("link"), {rel: "icon"}));
  const cv = document.createElement("canvas");
  cv.width = cv.height = N;
  const g = cv.getContext("2d");
  // The logo's "S", traced as a thick stroke with slanted ends (point-symmetric, like the wordmark's),
  // in a 276×252 box. Drawn as a shape rather than cut from the PNG, where the orbit crosses it.
  const S_W = 276, S_H = 252, S_STROKE = 54;
  function drawS(x, y, h, color) {
    const k = h / S_H;
    g.save();
    g.translate(x, y);
    g.scale(k, k);
    g.strokeStyle = g.fillStyle = color;
    g.lineWidth = S_STROKE;
    g.lineJoin = "round";
    g.beginPath();
    g.moveTo(236, 27);
    g.lineTo(85, 27);
    g.bezierCurveTo(22, 27, 20, 100, 80, 110);
    g.lineTo(196, 142);
    g.bezierCurveTo(256, 152, 254, 225, 191, 225);
    g.lineTo(40, 225);
    g.stroke();
    g.beginPath();  // slanted terminals
    g.moveTo(235, 0); g.lineTo(276, 0); g.lineTo(235, 54); g.closePath();
    g.moveTo(41, 252); g.lineTo(0, 252); g.lineTo(41, 198); g.closePath();
    g.fill();
    g.restore();
  }
  setTimeout(() => start());  // after the ring constants below are set

  const cx = 32, cy = 33, rx = 28, ry = 8.5, tilt = -0.36, period = 3200;
  const at = t => {  // a point on the tilted ring; sin(t) < 0 is the far side, behind the S
    const x = rx * Math.cos(t), y = ry * Math.sin(t);
    return [cx + x * Math.cos(tilt) - y * Math.sin(tilt), cy + x * Math.sin(tilt) + y * Math.cos(tilt)];
  };
  const ring = (from, to, alpha, width) => {
    g.beginPath();
    g.ellipse(cx, cy, rx, ry, tilt, from, to);
    g.strokeStyle = `rgba(171,209,198,${alpha})`;
    g.lineWidth = width;
    g.stroke();
  };
  const moon = t => {
    const front = Math.sin(t) >= 0;
    for (let i = 5; i >= 0; i--) {  // a short fading tail
      const [x, y] = at(t - i * 0.13);
      g.beginPath();
      g.arc(x, y, (front ? 4.2 : 3) * (1 - i * 0.13), 0, Math.PI * 2);
      g.fillStyle = i ? `rgba(171,209,198,${(front ? 0.28 : 0.14) * (1 - i / 6)})` : front ? "#CFF3EA" : "rgba(171,209,198,.55)";
      g.shadowColor = "#6CCFC8";
      g.shadowBlur = i ? 0 : front ? 10 : 4;
      g.fill();
    }
    g.shadowBlur = 0;
  };
  function draw(ms) {
    const t = (ms / period) * Math.PI * 2;
    g.clearRect(0, 0, N, N);
    g.beginPath();
    g.roundRect(0, 0, N, N, 15);
    g.fillStyle = "#312F2C";
    g.fill();
    ring(Math.PI, Math.PI * 2, 0.35, 2);  // far half
    if (Math.sin(t) < 0) moon(t);
    const h = 36, w = h * S_W / S_H;
    drawS(cx - w / 2, cy - h / 2 - 1, h, "#F2EFE9");
    ring(0, Math.PI, 0.8, 2.4);  // near half, over the S
    if (Math.sin(t) >= 0) moon(t);
    link.type = "image/png";
    link.href = cv.toDataURL("image/png");
  }
  function start() {
    if (still) return draw(period / 4);
    const t0 = performance.now();
    setInterval(() => draw(performance.now() - t0), 80);
  }
})();
