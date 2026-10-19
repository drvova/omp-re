// Fig 1 of the omp-re site: a key comparator that shows what `/re carry`
// decides. Built with the Anatomy kit (site/figure/kit, MIT). Run
// `node site/figure/carry/build.mjs` (add `--light` for the light theme); it
// writes carry.generated.html / carry-light.generated.html next to this
// script, which the site generator copies into the published site.
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import * as k from "../kit/iso-kit.mjs";
import { CASES, CUT, RECORDED, verdict } from "./model.mjs";

const HERE = import.meta.dirname;
const theme = process.argv.includes("--light") ? "light" : "dark";
const kitScript = () =>
  readFileSync(path.join(HERE, "..", "kit", "iso-kit.mjs"), "utf-8").replaceAll(
    /^export /gmu,
    ""
  );

const WIDTH = 640;
const HEIGHT = 400;

const PLATE = { d: 176, r: 8, w: 224, x: -152, y: -84 };
const PLATE_H = 12;
const FOOT_H = 5;

// Two rows: the recorded key behind (y < 0), the new build's key in front.
const ROWS = { back: -30, front: 30 };
const BED = { d: 36, w: 176, x: -138 };
const BED_TOP = 6;
const CARRIAGE_TOP = 9;
const VISE = { d: 28, w: 34, x: -124 };
const VISE_TOP = 21;
const JAW_TOP = 36;
const SPINE = [24, 30];
const [, CUT_BASE] = SPINE;
const STEP_H = 2.6;
const cutHeight = (level) => 2 + level * STEP_H;
const FIRST_CUT = -76;
const TIP_X = FIRST_CUT + CUT * RECORDED.length;
const SUPPORT = { d: 14, w: 14, x: 4 };

// The tracer bridge rides two rails along x and carries a stylus over each key.
const RAILS = { back: -70, front: 58 };
const RAIL_FROM = -98;
const RAIL_TO = 44;
const BUSHING = [62, 70];
const BEAM = [70, 78];
const DIAL_R = 15;
const DIAL_TOP = BEAM[1] + 8;
const ROD = 30;
const TIP_R = 2.2;
// The stylus hangs at its travel stop with nothing to trace: the rod stays in its bushing.
const LOWEST_TIP = BUSHING[0] + 1 - ROD;
/** One cut level of difference turns the needle a tenth of a turn. */
const PER_LEVEL = 0.1;
const centreOf = (i) => FIRST_CUT + CUT * i + CUT / 2;
const TRACE = [centreOf(0), centreOf(RECORDED.length - 1)];

const P = k.fitProjection(
  [
    ...k.boxCorners(PLATE, -PLATE_H - FOOT_H, 0),
    [TRACE[0], RAILS.back, DIAL_TOP + 4],
    [TRACE[1], RAILS.front + 12, DIAL_TOP],
  ],
  WIDTH,
  HEIGHT,
  { azimuth: 38, pad: 26 }
);

const at = (point) => k.iso(point, P);
const S = (paths, style) => k.solidSvg(paths, style);
const L = (d, style) => k.lineSvg(d, style);
const byDepth = (points) =>
  [...points].toSorted(
    (a, b) => k.depthOf([a[0], a[1], 0], P) - k.depthOf([b[0], b[1], 0], P)
  );
const screws = (points, z, size = 0.45) =>
  k.dotsSvg(
    points.map(([x, y]) => at([x, y, z])),
    { size }
  );
/** A knurled knob standing on `z`. */
const knurledKnob = ([x, y], r, z, h, count) => [
  S(k.cylinder(x, y, r, z, h, P, 28), { tone: "mid" }),
  L(k.knurl(x, y, r, z, z + h, count, P), { tone: "lo" }),
];

const plate = () => {
  const corner = k.corners(PLATE, 10);
  // Ruler strip along the front: the bridge's travel, one major tick per cut.
  const strip = { d: 7, r: 1, w: 108, x: -124, y: PLATE.y + PLATE.d - 14 };
  const ticks = k.topTicks(
    strip.x + 4,
    strip.x + strip.w - 4,
    6,
    2,
    strip.y + 0.8,
    0.6,
    [2, 3.6],
    P
  );
  // Label plate, front right: three rule lines stand for the engraved text.
  const label = { d: 17, r: 1.5, w: 58, x: -6, y: PLATE.y + PLATE.d - 20 };
  const rules = [
    [label.x + 6, label.x + 40],
    [label.x + 6, label.x + 50],
    [label.x + 6, label.x + 30],
  ];
  return [
    `<path class="iso-halo" d="${k.haloOf(PLATE, -PLATE_H - FOOT_H, PLATE_H, P)}"/>`,
    ...byDepth(k.corners(PLATE, 22)).flatMap(([x, y]) => [
      S(k.cylinder(x, y, 7, -PLATE_H - FOOT_H, 1.6, P, 28), { tone: "lo" }),
      S(k.cylinder(x, y, 5.4, -PLATE_H - FOOT_H + 1.6, FOOT_H - 1.6, P, 28), {
        tone: "mid",
      }),
    ]),
    S(k.slabOf(PLATE, -PLATE_H, PLATE_H, P, 8, 1.6), { tone: "mid" }),
    L(k.planOutline(k.insetPlan(PLATE, 5), 0, P), { tone: "lo" }),
    L(corner.map(([x, y]) => k.ring(x, y, 2.2, 0, P, 16)).join(""), {
      tone: "lo",
    }),
    screws(corner, 0, 0.5),
    S(k.slabOf(strip, 0, 0.6, P, 3), { crease: "none", tone: "lo" }),
    L(ticks.minor, { tone: "lo" }),
    L(ticks.major, { tone: "mid" }),
    screws(
      [
        [strip.x + 2, strip.y + 3.5],
        [strip.x + strip.w - 2, strip.y + 3.5],
      ],
      0.6
    ),
    S(k.slabOf(label, 0, 0.8, P, 4), { crease: "none", tone: "lo" }),
    L(k.planOutline(k.insetPlan(label, 1.6), 0.8, P, 4), { tone: "faint" }),
    ...rules.map(([from, to], i) => {
      const y = label.y + 6 + i * 5;
      return L(k.lineOnTop([from, y], [to, y], 0.8, P), {
        free: true,
        tone: "lo",
      });
    }),
    screws(
      [
        [label.x + 3, label.y + label.d / 2],
        [label.x + label.w - 3, label.y + label.d / 2],
      ],
      0.8
    ),
  ].join("");
};

const rail = (y) =>
  [
    S(
      k.slabOf(
        { d: 5, r: 1, w: RAIL_TO - RAIL_FROM, x: RAIL_FROM, y },
        0,
        3,
        P,
        3,
        0.4
      ),
      { tone: "mid" }
    ),
    screws(
      [RAIL_FROM + 8, RAIL_TO - 8].map((x) => [x, y + 2.5]),
      3
    ),
    ...[RAIL_FROM - 5, RAIL_TO].flatMap((x) => [
      S(k.slabOf({ d: 11, r: 1.2, w: 5, x, y: y - 3 }, 0, 7, P, 3, 0.5), {
        tone: "mid",
      }),
      screws([[x + 2.5, y + 2.5]], 7),
    ]),
  ].join("");

/** The sliding bed's extras: a ruler in cuts and the lead-screw knob. */
const slideworks = (plan, y0) => {
  const strip = { d: 3.6, r: 0.6, w: 120, x: plan.x + 8, y: y0 + 13.2 };
  const ticks = k.topTicks(
    strip.x + 2,
    strip.x + strip.w - 2,
    CUT / 2,
    2,
    strip.y + 0.4,
    BED_TOP + 0.4,
    [1.4, 2.6],
    P
  );
  const knob = [plan.x - 7, y0];
  return [
    S(k.slabOf(strip, BED_TOP, 0.4, P, 2), { crease: "none", tone: "lo" }),
    L(ticks.minor, { tone: "lo" }),
    L(ticks.major, { tone: "mid" }),
    S(
      k.slabOf(
        { d: 12, r: 1.5, w: 9, x: plan.x - 11, y: y0 - 6 },
        0,
        BED_TOP + 2,
        P,
        3,
        0.5
      ),
      { tone: "mid" }
    ),
    ...knurledKnob(knob, 5, BED_TOP + 2, 4, 28),
    L(
      k.lineOnTop([knob[0], knob[1]], [knob[0] + 4.4, knob[1]], BED_TOP + 6, P),
      { free: "end", tone: "hi" }
    ),
  ];
};

/** The fixed bed of one row: a slideway with two ways; the front one also slides. */
const bed = (y0, sliding) => {
  const plan = { ...BED, r: 3, y: y0 - BED.d / 2 };
  return [
    S(k.slabOf(plan, 0, BED_TOP, P, 5, 0.8), { tone: "mid" }),
    L(k.planOutline(k.insetPlan(plan, 3), BED_TOP, P, 5), { tone: "faint" }),
    ...[-12, 8].map((dy) =>
      S(
        k.slabOf(
          { d: 4, r: 0.8, w: plan.w - 10, x: plan.x + 5, y: y0 + dy },
          BED_TOP,
          1.4,
          P,
          2,
          0.3
        ),
        { crease: "none", tone: "lo" }
      )
    ),
    ...(sliding ? slideworks(plan, y0) : []),
    screws(
      [
        [plan.x + 3, plan.y + 3],
        [plan.x + plan.w - 3, plan.y + 3],
        [plan.x + plan.w - 3, plan.y + plan.d - 3],
      ],
      BED_TOP
    ),
  ].join("");
};

/** What rides on a bed: carriage plate, vise and the key's support block. */
const holder = (y0) => {
  const carriage = { d: 30, r: 2.5, w: 150, x: -130, y: y0 - 15 };
  const vise = { ...VISE, r: 2.5, y: y0 - VISE.d / 2 };
  const support = { ...SUPPORT, r: 1.5, y: y0 - SUPPORT.d / 2 };
  return [
    S(
      k.slabOf(
        carriage,
        BED_TOP + 1.4,
        CARRIAGE_TOP - BED_TOP - 1.4,
        P,
        4,
        0.5
      ),
      { tone: "mid" }
    ),
    screws(
      [-120, -40, 10].map((x) => [x, carriage.y + carriage.d - 2.4]),
      CARRIAGE_TOP,
      0.4
    ),
    S(k.slabOf(vise, CARRIAGE_TOP, VISE_TOP - CARRIAGE_TOP, P, 4, 0.6), {
      tone: "mid",
    }),
    L(k.planOutline(k.insetPlan(vise, 2.5), VISE_TOP, P, 4), { tone: "faint" }),
    // Clamp screw on the vise top.
    ...knurledKnob([vise.x + 7, y0 - 8], 3.6, VISE_TOP, 4, 20),
    S(k.slabOf(support, CARRIAGE_TOP, SPINE[0] - CARRIAGE_TOP, P, 3, 0.5), {
      tone: "mid",
    }),
    L(k.sideSeam(support, SPINE[0] - 4, P, 3), { tone: "faint" }),
  ].join("");
};

const jaw = (y0, side) => {
  const plan = {
    d: 6,
    r: 1,
    w: 18,
    x: VISE.x + 14,
    y: side < 0 ? y0 - 8 : y0 + 2,
  };
  return [
    S(k.slabOf(plan, VISE_TOP, JAW_TOP - VISE_TOP, P, 3, 0.5), { tone: "mid" }),
    screws(
      [
        [plan.x + 4, plan.y + 3],
        [plan.x + plan.w - 4, plan.y + 3],
      ],
      JAW_TOP,
      0.4
    ),
  ].join("");
};

/** A key standing on edge in the vise: bow, spine, then each cut, tip last. */
const key = (y0, bits) => {
  const bow = { d: 4, r: 1.5, w: 26, x: VISE.x + 10, y: y0 - 2 };
  const spine = {
    d: 4,
    r: 0.6,
    w: TIP_X - bow.x - bow.w + 6,
    x: bow.x + bow.w,
    y: y0 - 2,
  };
  return [
    S(k.slabOf(bow, SPINE[0] - 2, 24, P, 3, 0.4), { tone: "hi" }),
    L(k.sideRing([bow.x + 8, y0 + 2, SPINE[0] + 15], 3, "y", P, 20), {
      tone: "lo",
    }),
    S(k.slabOf(spine, SPINE[0], SPINE[1] - SPINE[0], P, 2, 0.3), {
      crease: "lo",
      tone: "hi",
    }),
    ...bits.map((level, i) =>
      S(
        k.slabOf(
          { d: 4, r: 0, w: CUT, x: FIRST_CUT + CUT * i, y: y0 - 2 },
          CUT_BASE,
          cutHeight(level),
          P,
          2,
          0.3
        ),
        { crease: "lo", tone: "hi" }
      )
    ),
  ].join("");
};

const plunger = () =>
  [
    S(k.cylinder(0, 0, TIP_R, 0, 2.2, P, 20), { lit: true, tone: "hi" }),
    S(k.cylinder(0, 0, 1.3, 2.2, ROD, P, 16), {
      crease: "none",
      lit: true,
      tone: "hi",
    }),
  ].join("");

const leg = (y) => {
  const shoe = { d: 15, r: 2, w: 22, x: -11, y: y - 5 };
  const column = { d: 9, r: 1.5, w: 10, x: -5, y: y - 2 };
  return [
    S(k.slabOf(shoe, 3, 6, P, 3, 0.5), { tone: "mid" }),
    screws(
      [
        [-7, y - 2],
        [7, y - 2],
      ],
      9,
      0.4
    ),
    S(k.slabOf(column, 9, BEAM[0] - 9, P, 3, 0.5), { tone: "mid" }),
    L(k.sideSeam(column, 40, P, 3), { tone: "faint" }),
  ].join("");
};

/** The differential dial on the beam's top: reads new minus recorded. */
const dial = () => {
  const ticks = k.radialTicks(
    0,
    0,
    DIAL_R - 2.6,
    40,
    5,
    DIAL_TOP,
    [1.2, 2.4],
    P
  );
  return [
    S(k.cylinder(0, 0, DIAL_R, BEAM[1], DIAL_TOP - BEAM[1], P, 64, 0.8), {
      crease: "lo",
      tone: "hi",
    }),
    L(k.knurl(0, 0, DIAL_R, DIAL_TOP - 3, DIAL_TOP, 72, P, 0.3), {
      tone: "lo",
    }),
    L(k.sideArc(0, 0, DIAL_R, DIAL_TOP - 3, P, 40), { tone: "faint" }),
    L(k.ring(0, 0, DIAL_R - 2, DIAL_TOP, P, 64), { tone: "lo" }),
    L(ticks.minor, { tone: "lo" }),
    L(ticks.major, { tone: "mid" }),
    L(k.ring(0, 0, 1.5, DIAL_TOP, P, 16), { tone: "mid" }),
    k.faceTextSvg(k.topMatrix([0, 7], DIAL_TOP, P, "x"), "Δ", {
      anchor: "middle",
      size: 2.6,
      tone: "lo",
    }),
    // Crown and its lug on the +x side.
    S(
      k.slabOf(
        { d: 4.4, r: 1, w: 4, x: DIAL_R - 1, y: -2.2 },
        BEAM[1] + 2,
        4.4,
        P,
        3
      ),
      { tone: "mid" }
    ),
    S(
      k.slabOf(
        { d: 6, r: 1.2, w: 2.4, x: DIAL_R + 2.6, y: -3 },
        BEAM[1] + 1.4,
        5.6,
        P,
        3
      ),
      { tone: "mid" }
    ),
  ];
};

const beam = () => {
  const plan = { d: 150, r: 2.5, w: 18, x: -9, y: RAILS.back - 5 };
  return [
    ...[ROWS.back, ROWS.front].flatMap((y) => [
      S(k.cylinder(0, y, 3.4, BUSHING[0], BUSHING[1] - BUSHING[0], P, 24), {
        tone: "mid",
      }),
      L(k.sideArc(0, y, 3.4, BUSHING[0] + 3, P, 16), { tone: "faint" }),
    ]),
    S(k.slabOf(plan, BEAM[0], BEAM[1] - BEAM[0], P, 4, 0.6), { tone: "mid" }),
    L(k.planOutline(k.insetPlan(plan, 3), BEAM[1], P, 4), { tone: "faint" }),
    screws(
      [plan.y + 5, ROWS.back, ROWS.front, plan.y + plan.d - 5].map((y) => [
        0,
        y,
      ]),
      BEAM[1]
    ),
    ...dial(),
    // Zeroing knob near the front leg.
    ...knurledKnob([0, RAILS.front - 10], 4, BEAM[1], 4, 24),
  ].join("");
};

const needleAt = (turn) => {
  const angle = turn * Math.PI * 2;
  return k.lineOnTop(
    [-Math.sin(angle) * 3, Math.cos(angle) * 3],
    [Math.sin(angle) * (DIAL_R - 2.2), -Math.cos(angle) * (DIAL_R - 2.2)],
    DIAL_TOP + 0.2,
    P
  );
};

const [START] = TRACE;
const topOf = (bits, i) => CUT_BASE + cutHeight(bits[i]);
const move = (part, by, inner) =>
  `<g data-part="${part}" transform="${k.translateAlong(P, by)}">${inner}</g>`;
const variants = CASES.filter((c) => c.bits && c.id !== "relocated");

const svg = k.figureSvg({
  body: [
    plate(),
    rail(RAILS.back),
    move("leg-back", [START, 0, 0], leg(RAILS.back)),
    bed(ROWS.back, false),
    holder(ROWS.back),
    jaw(ROWS.back, -1),
    key(ROWS.back, RECORDED),
    jaw(ROWS.back, 1),
    move("stylus-back", [START, ROWS.back, topOf(RECORDED, 0)], plunger()),
    bed(ROWS.front, true),
    move(
      "slide",
      [0, 0, 0],
      [
        holder(ROWS.front),
        jaw(ROWS.front, -1),
        ...variants.map(
          (c) =>
            `<g data-key="${c.id}"${c.id === "holds" ? "" : ' style="opacity:0"'}>${key(ROWS.front, c.bits)}</g>`
        ),
        jaw(ROWS.front, 1),
      ].join("")
    ),
    move("stylus-front", [START, ROWS.front, topOf(RECORDED, 0)], plunger()),
    rail(RAILS.front),
    move("leg-front", [START, 0, 0], leg(RAILS.front)),
    move("beam", [START, 0, 0], beam()),
    `<path data-part="needle" class="iso-line" data-tone="lit" data-free="start" d="${needleAt(0)}" transform="${k.translateAlong(P, [START, 0, 0])}" style="stroke-width:1.1"/>`,
  ],
  height: HEIGHT,
  label:
    "A key comparator on a surface plate. Two keys stand on edge in vises: behind, the key recorded in the report; in front, the key from the new build, on a slide that can shift it along. A bridge on two rails carries a stylus over each key, and a dial on the bridge reads the difference between the two cut depths as the bridge travels from the bow to the tip.",
  width: WIDTH,
});

const live = `
const P = ${JSON.stringify(P)};
const CASES = ${JSON.stringify(CASES.map((c) => ({ ...c, verdict: verdict(c) })))};
const RECORDED = ${JSON.stringify(RECORDED)};
const CUT = ${CUT}, FIRST_CUT = ${FIRST_CUT}, CUT_BASE = ${CUT_BASE}, STEP_H = ${STEP_H}, LOWEST = ${LOWEST_TIP};
const TRACE = ${JSON.stringify(TRACE)}, ROWS = ${JSON.stringify(ROWS)}, PER_LEVEL = ${PER_LEVEL};
const DIAL_R = ${DIAL_R}, DIAL_TOP = ${DIAL_TOP};
const stage = document.querySelector(".iso-stage");
const svg = stage.querySelector("svg");
const part = (name) => svg.querySelector('[data-part="' + name + '"]');
const legs = [part("leg-back"), part("leg-front"), part("beam")];
const styli = { back: part("stylus-back"), front: part("stylus-front") };
const needle = part("needle");
const slide = part("slide");
const keys = Object.fromEntries([...svg.querySelectorAll("[data-key]")].map((el) => [el.dataset.key, el]));
const readout = document.querySelector("[data-readout]");
const still = matchMedia("(prefers-reduced-motion: reduce)");
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const cutHeight = (level) => 2 + level * STEP_H;
const needleAt = ${needleAt.toString().replace("k.lineOnTop", "lineOnTop")};
const surfaceUnder = (bits, x, shift) => {
  if (!bits) return LOWEST;
  const i = Math.floor((x - shift - FIRST_CUT) / CUT);
  return i >= 0 && i < bits.length ? CUT_BASE + cutHeight(bits[i]) : CUT_BASE;
};
const cutAt = (x) => clamp(Math.floor((x - FIRST_CUT) / CUT), 0, RECORDED.length - 1);
let which = 0, phase = "load", phaseT = 0, bx = TRACE[0], target = bx;
let shift = 0, shiftTarget = 0, seen = { holds: 1 };
const tips = { back: { at: CUT_BASE, rate: 0 }, front: { at: CUT_BASE, rate: 0 } };
let frame = 0, last = 0, touring = true, visible = false, idle = 0, scrub = false;
const PHASES = { load: 0.9, align: 1.3, trace: 3.4, rest: 1.8 };
function load(i) {
  which = (i + CASES.length) % CASES.length;
  const c = CASES[which];
  phase = "load"; phaseT = 0; target = TRACE[0];
  shift = c.offset * CUT; shiftTarget = shift;
}
function caseLine(c, live) {
  if (phase === "rest" || (!touring && !scrub && phase !== "trace")) return c.verdict.line;
  if (phase === "align") return "relocated · profile found " + (-c.offset) + " cuts along · aligning";
  if (!live) return c.id + " · loading";
  const i = cutAt(bx);
  const d = tips.front.at - tips.back.at;
  return c.id + " · cut " + (i + 1) + " of " + RECORDED.length + " · Δ " + (d / STEP_H).toFixed(1);
}
function draw() {
  const c = CASES[which];
  for (const el of legs) el.setAttribute("transform", translateAlong(P, [bx, 0, 0]));
  styli.back.setAttribute("transform", translateAlong(P, [bx, ROWS.back, tips.back.at]));
  styli.front.setAttribute("transform", translateAlong(P, [bx, ROWS.front, tips.front.at]));
  slide.setAttribute("transform", translateAlong(P, [shift, 0, 0]));
  needle.setAttribute("transform", translateAlong(P, [bx, 0, 0]));
  needle.setAttribute("d", needleAt(clamp((tips.front.at - tips.back.at) / STEP_H, -4.5, 4.5) * PER_LEVEL));
  const text = caseLine(c, phase !== "load");
  if (readout.textContent !== text) readout.textContent = text;
  stage.setAttribute("aria-valuenow", String(which + 1));
  stage.setAttribute("aria-valuetext", text);
}
function fadeKeys(dt, calm) {
  const want = CASES[which].bits ? (CASES[which].id === "drifted" ? "drifted" : "holds") : null;
  for (const [id, el] of Object.entries(keys)) {
    const goal = id === want ? 1 : 0;
    const now = Number(el.style.opacity || (id === "holds" ? 1 : 0));
    const next = calm ? goal : now + (goal - now) * (1 - Math.exp(-dt / 0.18));
    el.style.opacity = String(Math.abs(goal - next) < 0.01 ? goal : next);
  }
}
function spring(tip, want, dt, calm) {
  const stiff = 520, drag = calm ? 2 * Math.sqrt(520) : 30;
  for (let i = 0; i < 4; i++) { tip.rate += ((want - tip.at) * stiff - tip.rate * drag) * dt / 4; tip.at += tip.rate * dt / 4; }
  if (Math.abs(want - tip.at) < 0.005 && Math.abs(tip.rate) < 0.005) { tip.at = want; tip.rate = 0; }
}
function tick(now) {
  const dt = last ? Math.min((now - last) / 1000, 1 / 30) : 1 / 60;
  last = now;
  const calm = still.matches;
  const c = CASES[which];
  if (touring) {
    phaseT += dt;
    if (phase === "load" && phaseT > PHASES.load) { phase = c.offset ? "align" : "trace"; phaseT = 0; shiftTarget = 0; }
    else if (phase === "align" && phaseT > PHASES.align) { phase = "trace"; phaseT = 0; }
    else if (phase === "trace") { target = TRACE[0] + (TRACE[1] - TRACE[0]) * Math.min(1, phaseT / PHASES.trace); if (phaseT > PHASES.trace) { phase = "rest"; phaseT = 0; } }
    else if (phase === "rest" && phaseT > PHASES.rest) load(which + 1);
  }
  if (phase === "align" || !touring) shiftTarget = 0;
  shift = calm ? shiftTarget : shift + (shiftTarget - shift) * (1 - Math.exp(-dt / 0.35));
  if (Math.abs(shiftTarget - shift) < 0.01) shift = shiftTarget;
  bx = calm ? target : bx + (target - bx) * (1 - Math.exp(-dt / 0.12));
  if (Math.abs(target - bx) < 0.01) bx = target;
  spring(tips.back, surfaceUnder(RECORDED, bx, 0), dt, calm);
  spring(tips.front, surfaceUnder(c.bits, bx, shift), dt, calm);
  fadeKeys(dt, calm);
  draw();
  const settled = !touring && bx === target && shift === shiftTarget && tips.back.rate === 0 && tips.front.rate === 0;
  frame = visible && !settled ? requestAnimationFrame(tick) : 0;
}
const run = () => { if (!frame && visible) { last = 0; frame = requestAnimationFrame(tick); } };
const quiet = () => { touring = false; clearTimeout(idle); idle = setTimeout(() => { if (!still.matches) { touring = true; scrub = false; load(which + 1); run(); } }, 4200); };
const choose = (i) => { load(i); quiet(); phase = "rest"; target = TRACE[1]; run(); };
new IntersectionObserver((entries) => { visible = entries[entries.length - 1].isIntersecting; if (visible) run(); }, { rootMargin: "120px 0px" }).observe(stage);
if (still.matches) { touring = false; phase = "rest"; target = TRACE[1]; bx = target; }
stage.addEventListener("pointermove", (event) => {
  const box = svg.getBoundingClientRect();
  const share = clamp(((event.clientX - box.left) / box.width - 0.3) / 0.45, 0, 1);
  quiet(); scrub = true; phase = "trace"; shiftTarget = 0;
  target = TRACE[0] + share * (TRACE[1] - TRACE[0]);
  run();
});
stage.addEventListener("pointerleave", () => { scrub = false; phase = "rest"; run(); });
stage.addEventListener("click", () => choose(which + 1));
stage.addEventListener("keydown", (event) => {
  const n = Number(event.key);
  if (n >= 1 && n <= CASES.length) { event.preventDefault(); choose(n - 1); return; }
  if (event.key === "Enter" || event.key === " ") { event.preventDefault(); choose(which + 1); return; }
  const step = event.key === "ArrowRight" || event.key === "ArrowUp" ? 1 : event.key === "ArrowLeft" || event.key === "ArrowDown" ? -1 : 0;
  if (!step) return;
  event.preventDefault();
  quiet(); scrub = true; phase = "trace"; shiftTarget = 0;
  target = clamp(FIRST_CUT + CUT * (cutAt(target) + step) + CUT / 2, TRACE[0], TRACE[1]);
  run();
});
load(0);
tips.back.at = surfaceUnder(RECORDED, bx, 0);
tips.front.at = surfaceUnder(CASES[0].bits, bx, 0);
draw();
`;

const body = k.plateHtml({
  body: `<div class="iso-stage" tabindex="0" role="slider" aria-label="Carry comparator: keys 1 to 4 load holds, relocated, drifted or broken; arrow keys move the stylus cut by cut" aria-valuemin="1" aria-valuemax="4" aria-valuenow="1">${svg}</div>`,
  caption:
    "What /re carry decides for one cited command. The back key is the output the report recorded; the front key is the same command re-run on the new build. Holds: every cut matches. Relocated: the same profile sits further along, so the slide re-aligns it (a fingerprint has to match at least 80%). Drifted: a cut differs and the needle swings. Broken: there is nothing in the vise to trace.",
  fig: "Fig 1",
  hint: "Press 1–4 or click to load a build",
  keys: [
    {
      label: "Styli and needle: what moves when the outputs differ",
      mark: "lit",
    },
    { label: "Keys: recorded behind, new build in front", mark: "raised" },
  ],
  readout: "holds · loading",
  title: "/re carry",
});

const out =
  theme === "light" ? "carry-light.generated.html" : "carry.generated.html";
writeFileSync(
  path.join(HERE, out),
  k.pageHtml({
    body,
    script: kitScript() + live,
    theme,
    title: "/re carry",
    width: 680,
  })
);
console.log("wrote", out);

// The same figure as a fragment for the site's home page: kit styles (all
// scoped to `.iso`), the card, and its script. The fragment follows the
// visitor's light or dark setting instead of a build-time theme.
const FOLLOW_SCHEME = `(() => {
  const plate = document.currentScript.previousElementSibling;
  const dark = matchMedia("(prefers-color-scheme: dark)");
  const set = () => { plate.dataset.theme = dark.matches ? "dark" : "light"; };
  set();
  dark.addEventListener("change", set);
})();`;
const moduleScript = (kitScript() + live).replaceAll(
  /<\/script/giu,
  "<\\/script"
);
writeFileSync(
  path.join(HERE, "carry.fragment.generated.html"),
  `<style>${k.ISO_CSS}</style><div class="iso iso-embed" data-theme="light">${body}</div><script>${FOLLOW_SCHEME}</script><script type="module">${moduleScript}</script>\n`
);
