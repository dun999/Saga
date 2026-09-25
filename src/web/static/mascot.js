// Saga's mascot: a lavender memory blob that carries a parcel over to a teammate and hands it off.
// Pixel art drawn as SVG, animated on one JS timeline so every move eases in and out.
//   SagaMascot.mount(el, {loop: true})              landing: loops while on screen
//   SagaMascot.mount(el, {loop: false, onDone})     app: plays the delivery once
(() => {
  const CSS = `
.sm { --saga: #92A9E1; --saga-hi: #C9D5F4; --saga-line: #3F57A0; --cheek: #F2A2A0; --ink: #2B2A27;
  --buddy: #D97757; --buddy-eye: #2B2A27; --box: #D8B27A; --box-lid: #E9CB98; --box-edge: #A97F45; --box-shade: #BF9558;
  --ribbon: #6F87CF; --heart: #E5687A; --spark: #B9C8F2;
  position: relative; width: 100%; aspect-ratio: 640 / 232; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) .sm { --saga-line: #2A3C78; --ink: #EDE8DF; --buddy-eye: #1B1A18; } }
:root[data-theme="dark"] .sm { --saga-line: #2A3C78; --ink: #EDE8DF; --buddy-eye: #1B1A18; }
.sm-stage { position: absolute; left: 0; top: 0; width: 640px; height: 232px; transform-origin: top left; }
.sm-a, .sm-fx { position: absolute; left: 0; bottom: 14px; will-change: transform; }
.sm-a { transform-origin: 50% 100%; }
.sm svg { display: block; shape-rendering: crispEdges; overflow: visible; }
.sm-blink { transform-box: fill-box; transform-origin: center; animation: sm-blink 3.4s infinite; }
.sm-buddy .sm-blink { animation-delay: 1.3s; }
@keyframes sm-blink { 0%, 93%, 100% { transform: none; } 96% { transform: scaleY(.12); } }
.sm-spark { width: 6px; height: 6px; background: var(--spark); opacity: 0; }
@media (prefers-reduced-motion: reduce) { .sm-blink { animation: none; } }`;

  // One character per pixel. `e` pixels are eyes: they blink and glance.
  const SAGA = [
    ".....oooooo.....", "...oobbbbbboo...", "..obbllbbbbbbo..", ".obbllbbbbbbbbo.", ".obbbbbbbbbbbbo.",
    "obbbeebbbbeebbbo", "obbbeebbbbeebbbo", "obbcbbbkkbbbcbbo", "obbbbbbbbbbbbbbo", "obbbmbbbbbbmmbbo",
    ".obbbbbmmbbbbbo.", "..obbbbbbbbbbo..", "...oooooooooo...", ".....ff..gg.....", "....fff..ggg....",
  ];
  const BUDDY = [
    "..rrrrrrrrrr..", "..rrrrrrrrrr..", "..rrerrrrerr..", "rrrrerrrrerrrr", "rrrrrrrrrrrrrr",
    "..rrrrrrrrrr..", "..rrrrrrrrrr..", "..r.r....r.r..", "..r.r....r.r..",
  ];
  // Eye shapes per mood, as [column, row] pixels on the character's own grid. Each shape is drawn once
  // and shown or hidden, so a mood change is instant and crisp.
  const SAGA_EYES = {
    normal:  [[4,5],[5,5],[4,6],[5,6], [10,5],[11,5],[10,6],[11,6]],
    happy:   [[3,6],[4,5],[5,5],[6,6], [9,6],[10,5],[11,5],[12,6]],                 // ^ ^
    focus:   [[3,6],[4,6],[5,6], [10,6],[11,6],[12,6]],                             // – – concentrating
    content: [[3,5],[4,6],[5,6],[6,5], [9,5],[10,6],[11,6],[12,5]],                 // ‿ ‿ eyes closed, pleased
  };
  const BUDDY_EYES = {
    normal:    [[4,2],[4,3], [9,2],[9,3]],
    surprised: [[4,1],[4,2],[4,3],[5,1],[5,2],[5,3], [8,1],[8,2],[8,3],[9,1],[9,2],[9,3]],
    happy:     [[3,3],[4,2],[5,3], [8,3],[9,2],[10,3]],                             // ^ ^
    delighted: [[3,1],[5,1],[3,2],[4,2],[5,2],[4,3], [8,1],[10,1],[8,2],[9,2],[10,2],[9,3]],  // ♥ ♥ heart eyes
  };
  const BOX = ["..t..t..", "...tt...", "LLLtLLLL", "EEEtEEEE", "BBBtBBBB", "BBBtBBBB", "BBBtBBBB", "SSSSSSSS"];
  const HEART = [".hh.hh.", "hhhhhhh", "hhhhhhh", ".hhhhh.", "..hhh..", "...h..."];
  const COLOR = {
    o: "var(--saga-line)", f: "var(--saga-line)", g: "var(--saga-line)", b: "var(--saga)", l: "var(--saga-hi)", k: "var(--saga-line)", c: "var(--cheek)", m: "var(--saga-hi)",
    r: "var(--buddy)", t: "var(--ribbon)", L: "var(--box-lid)", E: "var(--box-edge)", B: "var(--box)", S: "var(--box-shade)",
    h: "var(--heart)",
  };
  function draw(svg, map, size, eyeColor, skin, moods) {
    const w = map[0].length * size, h = map.length * size;
    svg.setAttribute("width", w); svg.setAttribute("height", h); svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    let body = "", eyes = "", footL = "", footR = "";
    const px = (x, y, fill) => `<rect x="${x * size}" y="${y * size}" width="${size}" height="${size}" fill="${fill}"/>`;
    map.forEach((row, y) => [...row].forEach((ch, x) => {
      if (ch === ".") return;
      if (ch === "e") { eyes += px(x, y, eyeColor); body += px(x, y, skin); }  // skin under the eye: no hole when it glances
      else if (ch === "f") footL += px(x, y, COLOR[ch]);
      else if (ch === "g") footR += px(x, y, COLOR[ch]);
      else body += px(x, y, COLOR[ch]);
    }));
    if (moods) eyes = Object.entries(moods).map(([name, cells]) =>
      `<g data-mood="${name}"${name === "normal" ? "" : ' display="none"'}>${cells.map(([x, y]) => px(x, y, eyeColor)).join("")}</g>`).join("");
    svg.innerHTML = `<g class="sm-foot">${footL}</g><g class="sm-foot">${footR}</g>` + body +
                    (eyes ? `<g class="sm-eyes"><g class="sm-blink">${eyes}</g></g>` : "");
    const [fl, fr] = svg.querySelectorAll(".sm-foot");
    const blink = svg.querySelector(".sm-blink");
    let current = "normal";
    const mood = name => {  // swap eye shape; only the normal eyes blink
      if (!moods || name === current) return;
      svg.querySelector(`[data-mood="${current}"]`).setAttribute("display", "none");
      svg.querySelector(`[data-mood="${name}"]`).removeAttribute("display");
      blink.style.animationName = name === "normal" ? "" : "none";
      current = name;
    };
    return { w, h, eyes: svg.querySelector(".sm-eyes"), feet: footL ? [fl, fr] : null, mood };
  }

  const clamp = (v, a = 0, b = 1) => Math.min(b, Math.max(a, v));
  const seg = (t, a, b) => clamp((t - a) / (b - a));
  const lerp = (a, b, p) => a + (b - a) * p;
  const inOut = p => p < .5 ? 4 * p * p * p : 1 - Math.pow(-2 * p + 2, 3) / 2;
  const outBack = p => 1 + 2.4 * Math.pow(p - 1, 3) + 1.4 * Math.pow(p - 1, 2);
  const pulse = p => Math.sin(Math.PI * clamp(p));
  const LOOP = 8.4, ONCE = 6.6, STILL = 4.4;   // seconds; STILL is the handover, shown when motion is off
  const HOME = 70, STOP = 318, BUDDY_X = 452;

  function mount(root, { loop = true, onDone } = {}) {
    if (!document.getElementById("sm-css")) {
      const st = document.createElement("style"); st.id = "sm-css"; st.textContent = CSS; document.head.appendChild(st);
    }
    root.classList.add("sm");
    root.innerHTML = `<div class="sm-stage"><div class="sm-a sm-buddy"><svg></svg></div><div class="sm-a sm-saga"><svg></svg></div>
      <div class="sm-a sm-box"><svg></svg></div><div class="sm-fx sm-heart"><svg></svg></div></div>`;
    const q = s => root.querySelector(s), stage = q(".sm-stage");
    const saga = draw(q(".sm-saga svg"), SAGA, 7, "var(--ink)", "var(--saga)", SAGA_EYES);
    const buddy = draw(q(".sm-buddy svg"), BUDDY, 7, "var(--buddy-eye)", "var(--buddy)", BUDDY_EYES);
    const box = draw(q(".sm-box svg"), BOX, 5);
    draw(q(".sm-heart svg"), HEART, 4);
    const sparks = Array.from({ length: 8 }, (_, i) => {
      const s = document.createElement("div"); s.className = "sm-fx sm-spark"; stage.appendChild(s);
      const a = -Math.PI / 2 + (i - 3.5) * 0.42; return { s, dx: Math.cos(a), dy: -Math.sin(a) };
    });
    const put = (n, x, y, extra = "") => { n.style.transform = `translate(${x}px, ${-y}px) ${extra}`; };
    const el = { saga: q(".sm-saga"), buddy: q(".sm-buddy"), box: q(".sm-box"), heart: q(".sm-heart") };

    function render(t) {
      // Saga: walk over, stop, lean in to give, turn, walk home.
      let x = HOME, lift = 0, sx = 1, sy = 1, rot = 0, face = 1, look = 0, stepL = [0, 0], stepR = [0, 0];
      if (t >= 0.5 && t < 3.1 || t >= 5.6 && t < 7.8) {
        const going = t < 3.1, p = going ? seg(t, 0.5, 3.1) : seg(t, 5.6, 7.8);
        x = going ? lerp(HOME, STOP, inOut(p)) : lerp(STOP, HOME, inOut(p));
        const amp = Math.min(1, Math.sin(Math.PI * p) * 1.6);          // steps fade in and out with the speed
        const phase = (t - (going ? 0.5 : 5.6)) * Math.PI * 2 * 1.8;
        // Feet take turns: the lifted one swings forward, the planted one pushes back. The body stays down
        // and only rises a hair and waddles, so Saga walks instead of hovering.
        const foot = ph => [-Math.cos(ph) * 8 * amp, Math.max(0, Math.sin(ph)) * 8 * amp];
        stepL = foot(phase); stepR = foot(phase + Math.PI);
        lift = Math.abs(Math.cos(phase)) * 1.5 * amp;
        sy = 1 - 0.025 * amp * Math.abs(Math.sin(phase)); sx = 1 / sy;
        rot = Math.sin(phase) * 3 * amp; look = going ? 1 : -1;
        if (!going) face = -1;
      } else if (t >= 3.1 && t < 5.6) {
        x = STOP; look = 1;
        sy = 1 - 0.08 * pulse(seg(t, 3.1, 3.45)); sx = 1 / sy;             // settle
        rot += 9 * pulse(seg(t, 3.5, 4.2));                                // lean in to hand it over
        if (t > 4.8) { face = Math.cos(Math.PI * inOut(seg(t, 5.2, 5.55))); look = face >= 0 ? 1 : -1; }
      } else if (t >= 7.8) {
        face = -Math.cos(Math.PI * inOut(seg(t, 7.85, 8.2))); look = face >= 0 ? 0 : -1;
        sy = 1 - 0.07 * pulse(seg(t, 7.8, 8.1)); sx = 1 / sy;
      }
      const fx = Math.abs(face) < 0.08 ? 0.08 * Math.sign(face || 1) : face;
      put(el.saga, x, lift, `rotate(${rot}deg) scale(${sx * fx}, ${sy})`);
      saga.mood(t >= 3.45 && t < 4.25 ? "focus"        // aiming the handover
              : t >= 4.25 && t < 6.4 ? "happy"         // Claude caught it
              : t >= 6.4 && t < 7.9 ? "content"        // strolling home, pleased
              : "normal");
      saga.eyes.style.transform = `translateX(${(face < 0 ? -look : look) * 3}px)`;
      saga.feet[0].style.transform = `translate(${stepL[0]}px, ${lift - stepL[1]}px)`;  // feet stay on the ground
      saga.feet[1].style.transform = `translate(${stepR[0]}px, ${lift - stepR[1]}px)`;

      // The teammate: watches Saga come over, catches, hops twice for joy.
      let csy = 1 - 0.12 * pulse(seg(t, 4.25, 4.5));
      const hop1 = seg(t, 4.55, 5.0), hop2 = seg(t, 5.05, 5.5);
      const cl = 24 * pulse(hop1) + 18 * pulse(hop2), crot = -6 * pulse(hop1) + 5 * pulse(hop2);
      csy -= 0.1 * Math.max(pulse(seg(t, 4.98, 5.1)), pulse(seg(t, 5.48, 5.62)));
      put(el.buddy, BUDDY_X, cl, `rotate(${crot}deg) scale(${1 / csy}, ${csy})`);
      buddy.mood(t >= 3.6 && t < 4.25 ? "surprised"   // a parcel, for me?
               : t >= 4.25 && t < 5.7 ? "happy"        // caught it: hop hop
               : t >= 5.7 && t < 6.6 ? "delighted"     // it opens into sparkles
               : t >= 6.6 && t < 7.4 ? "happy"
               : "normal");
      buddy.eyes.style.transform = `translateX(${t > 1.4 && t < 6.2 ? -4 : 0}px)`;  // eyes follow Saga

      // The parcel: pops onto Saga's head, rides along, arcs over, lands, opens into sparkles.
      let bx, by, bs = 1, br = 0, bo = 1;
      const buddyMid = BUDDY_X + buddy.w / 2 - box.w / 2;
      if (t < 3.6) {
        bx = x + saga.w / 2 - box.w / 2 + rot * 1.2; by = saga.h * sy + lift - 2; br = rot * 0.6;
        bs = t < 0.5 ? outBack(seg(t, 0.05, 0.5)) : 1; bo = t < 0.05 ? 0 : 1;
      } else if (t < 4.25) {
        const p = inOut(seg(t, 3.6, 4.25));
        bx = lerp(STOP + saga.w / 2 - box.w / 2, buddyMid, p);
        by = lerp(saga.h - 2, buddy.h - 1, p) + 48 * Math.sin(Math.PI * p);
        br = -14 * Math.sin(Math.PI * p);
      } else if (t < 6.2) {
        bx = buddyMid + crot * 1.2; by = buddy.h * csy + cl - 1; br = crot;
        const open = seg(t, 5.7, 6.2); bs = 1 + 0.35 * open; bo = 1 - inOut(open);
      } else { bx = buddyMid; by = buddy.h; bo = 0; }
      el.box.style.opacity = bo;
      put(el.box, bx, by, `rotate(${br}deg) scale(${bs})`);

      const hp = seg(t, 4.6, 6.0);
      el.heart.style.opacity = hp > 0 && hp < 1 ? Math.min(1, hp * 5, (1 - hp) * 3) : 0;
      put(el.heart, BUDDY_X + buddy.w / 2 + 26, buddy.h + 30 + hp * 40, `scale(${0.6 + 0.4 * outBack(clamp(hp * 3))})`);
      const sp = seg(t, 5.75, 6.5);
      for (const { s, dx, dy } of sparks) {
        s.style.opacity = sp > 0 && sp < 1 ? 1 - sp : 0;
        put(s, buddyMid + box.w / 2 - 3 + dx * 46 * inOut(sp), buddy.h + 20 + dy * 46 * inOut(sp), `scale(${1 - sp * 0.6})`);
      }
    }

    const fit = () => { stage.style.transform = `scale(${root.clientWidth / 640})`; };
    const ro = new ResizeObserver(fit); ro.observe(root); fit();
    const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
    let raf = 0, start = 0, visible = !loop, elapsed = 0;
    const tick = now => {
      const t = elapsed + (now - start) / 1000;
      if (!loop && t >= ONCE) { render(ONCE); raf = 0; onDone?.(); return; }
      render(loop ? t % LOOP : t);
      raf = requestAnimationFrame(tick);
    };
    const play = () => { if (raf || calm) return; start = performance.now(); raf = requestAnimationFrame(tick); };
    const pause = () => { if (!raf) return; cancelAnimationFrame(raf); raf = 0; elapsed += (performance.now() - start) / 1000; };
    render(calm ? STILL : 0);
    if (calm) { if (!loop) setTimeout(() => onDone?.(), 1600); }
    else if (loop) {  // only animate while someone can see it
      new IntersectionObserver(([e]) => { visible = e.isIntersecting; visible ? play() : pause(); }, { threshold: 0.2 }).observe(root);
    } else play();
    return { play, pause, render };
  }

  window.SagaMascot = { mount };
})();
