// The praetore-mcp dashboard page (src/dashboard/app.js) run on a minimal
// stand-in DOM and 2D canvas (no npm packages), fed with real /api/state
// answers from tests-js/fixtures (rebuilt by fixtures/make.sh). The canvas
// records every fillText and the page's requestAnimationFrame calls, so the
// tests check what is drawn and written, not the source text.
// Run: node --test crates/praetore-mcp/tests-js/
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

const here = new URL("./", import.meta.url);
const source = readFileSync(new URL("../src/dashboard/app.js", here), "utf8");
const css = readFileSync(new URL("../src/dashboard/app.css", here), "utf8");
const fixture = (name) => JSON.parse(readFileSync(new URL(`fixtures/${name}.json`, here), "utf8"));

// The real color tokens, so a test can tell the wall from the HUD line.
const tokens = {};
for (const [, name, value] of css.split(":root {")[1].split("}")[0].matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) {
  tokens[name] = value.trim();
}

// ---------- stand-in DOM ----------

class Node {
  constructor(tag) {
    this.tagName = String(tag).toUpperCase();
    this.children = [];
    this.parentElement = null;
    this.text = "";
    this.attributes = new Map();
    this.listeners = new Map();
    this.hidden = false;
    this.className = "";
    this.style = { cssText: "" };
    this.value = "";
    this.checked = false;
    this.scrollTop = 0;
    this.clientWidth = 1200;
    this.width = 1200;
    const node = this;
    this.classList = {
      set: new Set(),
      add(c) { this.set.add(c); },
      remove(c) { this.set.delete(c); },
      toggle(c, on) { if (on ?? !this.set.has(c)) this.set.add(c); else this.set.delete(c); },
      contains(c) { return this.set.has(c) || node.className.split(" ").includes(c); },
    };
  }
  get textContent() {
    return this.children.length ? this.children.map((c) => c.textContent).join("") : this.text;
  }
  set textContent(value) {
    this.children = [];
    this.text = String(value);
  }
  set innerHTML(_value) {
    throw new Error("innerHTML is never used");
  }
  append(...nodes) {
    for (const n of nodes) {
      const child = n instanceof Node ? n : new Text(String(n));
      child.parentElement = this;
      this.children.push(child);
    }
  }
  replaceChildren(...nodes) {
    this.children = [];
    this.text = "";
    this.append(...nodes);
  }
  remove() {
    if (this.parentElement) this.parentElement.children = this.parentElement.children.filter((c) => c !== this);
  }
  setAttribute(k, v) { this.attributes.set(k, String(v)); }
  getAttribute(k) { return this.attributes.has(k) ? this.attributes.get(k) : null; }
  removeAttribute(k) { this.attributes.delete(k); }
  addEventListener(type, fn) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(fn);
  }
  removeEventListener() {}
  dispatchEvent() { return true; }
  focus() {}
  matches() { return false; }
  getBoundingClientRect() { return { width: this.width, height: 600, top: 0, left: 0 }; }
  all() {
    return [this, ...this.children.flatMap((c) => (c instanceof Text ? [] : c.all()))];
  }
  getContext() {
    if (!this.ctx) this.ctx = recorder();
    return this.ctx;
  }
}

class Text extends Node {
  constructor(text) {
    super("#text");
    this.text = text;
  }
  get textContent() { return this.text; }
}

// A 2D context that records what is written and in which color.
function recorder() {
  const ctx = {
    texts: [],
    fillStyle: "",
    strokeStyle: "",
    font: "",
    textAlign: "left",
    lineWidth: 1,
    fillText(text, x, y) { ctx.texts.push({ text: String(text), color: ctx.fillStyle, x, y, align: ctx.textAlign }); },
    measureText(text) { return { width: String(text).length * 6 }; },
    createLinearGradient() { return { addColorStop() {} }; },
    clear() { ctx.texts = []; },
  };
  for (const name of ["clearRect", "fillRect", "strokeRect", "beginPath", "moveTo", "lineTo", "stroke", "fill",
    "arc", "setLineDash", "setTransform", "save", "restore", "closePath", "rect"]) {
    ctx[name] = () => {};
  }
  return ctx;
}

// ---------- a page ----------

// Loads app.js in a fresh context. `reduced` is the reduced-motion setting;
// `width` is the width of every element (the canvases among them); the clock
// and the frames are driven by the test.
function page({ reduced = false, hash = "#/live", now = Date.parse("2026-01-01T00:00:00Z"), width = 1200 } = {}) {
  const byId = new Map();
  const getElementById = (id) => {
    if (!byId.has(id)) {
      const node = new Node(id === "hud" || id === "chain" ? "canvas" : "div");
      node.width = width;
      node.clientWidth = width;
      node.setAttribute("id", id);
      byId.set(id, node);
    }
    return byId.get(id);
  };
  const tbody = new Node("tbody");
  const docListeners = new Map();
  const winListeners = new Map();
  const frames = [];
  let frameId = 0;
  const clock = { now: 1000 };
  let answer = null;
  const document = {
    hidden: false,
    title: "",
    activeElement: null,
    documentElement: new Node("html"),
    getElementById,
    createElement: (tag) => new Node(tag),
    querySelector: (selector) => (selector === "#table tbody" ? tbody : null),
    querySelectorAll: (selector) => {
      const nodes = [...byId.values()].flatMap((n) => n.all());
      if (selector === "[data-evidence-id]") return nodes.filter((n) => n.getAttribute("data-evidence-id") !== null);
      return [];
    },
    contains: () => true,
    addEventListener: (type, fn) => {
      if (!docListeners.has(type)) docListeners.set(type, []);
      docListeners.get(type).push(fn);
    },
  };
  const storage = new Map();
  const copied = [];
  const context = {
    console,
    Node,
    document,
    location: { hash },
    history: { replaceState() {} },
    navigator: { language: "es", clipboard: { writeText: async (text) => { copied.push(String(text)); } } },
    localStorage: {
      getItem: (k) => (storage.has(k) ? storage.get(k) : null),
      setItem: (k, v) => storage.set(k, String(v)),
      removeItem: (k) => storage.delete(k),
    },
    matchMedia: (query) => ({
      matches: query.includes("reduced-motion") ? reduced : false,
      addEventListener() {},
    }),
    getComputedStyle: () => ({ getPropertyValue: (name) => tokens[name] ?? "" }),
    performance: { now: () => clock.now },
    requestAnimationFrame: (fn) => { frameId += 1; frames.push({ id: frameId, fn }); return frameId; },
    cancelAnimationFrame: (id) => {
      const i = frames.findIndex((f) => f.id === id);
      if (i >= 0) frames.splice(i, 1);
    },
    setInterval: () => 0,
    clearInterval: () => {},
    setTimeout: () => 0,
    clearTimeout: () => {},
    fetch: async () => ({ ok: true, status: 200, json: async () => structuredClone(answer) }),
    devicePixelRatio: 1,
    scrollTo() {},
    addEventListener: (type, fn) => {
      if (!winListeners.has(type)) winListeners.set(type, []);
      winListeners.get(type).push(fn);
    },
    URLSearchParams,
    Intl,
    structuredClone,
  };
  context.window = context;
  vm.createContext(context);
  // A fixed "now", so pending calls in the fixtures are not expired.
  vm.runInContext(`{
    const Real = Date;
    globalThis.Date = class extends Real {
      constructor(...a) { if (a.length === 0) super(${now}); else super(...a); }
      static now() { return ${now}; }
    };
  }`, context);
  vm.runInContext(`${source}
;globalThis.__page = {
  get state() { return state; },
  hud, chain, load, shown,
};`, context, { filename: "app.js" });
  const p = context.__page;
  let requested = 0;
  return {
    byId,
    frames,
    clock,
    // What the page wrote to the clipboard, in order.
    copied,
    hud: p.hud,
    // Starts the page on `state`, as the browser does on DOMContentLoaded.
    async start(state) {
      answer = state;
      for (const fn of docListeners.get("DOMContentLoaded") || []) fn();
      await settle();
    },
    // One poll of /api/state answering `state`.
    async poll(state) {
      answer = state;
      await p.load();
      await settle();
    },
    // Runs the requested frames, `ms` apart, until none is asked for.
    runFrames(ms = 16, max = 600) {
      let run = 0;
      while (frames.length && run < max) {
        clock.now += ms;
        const batch = frames.splice(0);
        for (const f of batch) f.fn(clock.now);
        run += 1;
      }
      return run;
    },
    requestedSince() {
      const n = frameId - requested;
      requested = frameId;
      return n;
    },
    go(next) {
      context.location.hash = next;
      for (const fn of winListeners.get("hashchange") || []) fn();
    },
    canvas(id) { return getElementById(id).getContext(); },
    text(id) { return getElementById(id).textContent; },
    table() { return tbody.textContent; },
    tbody,
    shown: (text) => p.shown(text),
    // Runs `code` in the page's context (before start, to stand in for a browser).
    run: (code) => vm.runInContext(code, context),
  };
}

async function settle() {
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));
}

// The pending fixture's notice, unexpired at the page's "now".
function pendingNow() {
  const state = fixture("pending");
  return Date.parse(state.pending[0].expires_at) - 60_000;
}

// The texts drawn on a canvas in the last picture (after clearing the log).
function drawn(p, id, run = () => p.runFrames()) {
  const ctx = p.canvas(id);
  ctx.clear();
  run();
  return ctx.texts;
}

// ---------- tests ----------

test("the chain is cut where verify failed, with verify's reason", async () => {
  const state = fixture("cut");
  const reason = state.page.receipts.find((r) => r.verified === false).order;
  assert.match(reason, /do not follow the previous entry/);
  const p = page({ hash: "#/chain" });
  await p.start(state);
  const texts = p.canvas("chain").texts.map((t) => t.text);
  const cut = texts.find((t) => t.startsWith("la cadena se corta aquí: "));
  assert.ok(cut, texts.join("\n"));
  assert.ok(reason.startsWith(cut.slice("la cadena se corta aquí: ".length).replace(/…$/, "")), cut);
  assert.equal(texts.filter((t) => t === "✕").length, 1, "one receipt fails verify");
  assert.equal(texts.filter((t) => t === "✓").length, 2);
  // The list view says the same: one row fails verify.
  p.byId.get("chain-list").listeners.get("click")[0]();
  assert.equal(p.table().split("✕").length - 1, 1, p.table());
  assert.equal(p.table().split("✓").length - 1, 2, p.table());
});

test("a gap is said to be left out by the filter only when a filter is on", async () => {
  const filtered = fixture("healthy-allow");
  assert.equal(filtered.page.filters.decision, "ALLOW");
  assert.deepEqual(filtered.page.receipts.map((r) => r.seq), [3, 0]);
  const p = page({ hash: "#/chain" });
  await p.start(filtered);
  let texts = p.canvas("chain").texts.map((t) => t.text);
  assert.ok(texts.includes("2 recibos omitidos por el filtro"), texts.join("\n"));

  // The same two receipts with no filter on: no such words.
  const unfiltered = structuredClone(filtered);
  for (const key of Object.keys(unfiltered.page.filters)) unfiltered.page.filters[key] = null;
  const q = page({ hash: "#/chain" });
  await q.start(unfiltered);
  texts = q.canvas("chain").texts.map((t) => t.text);
  assert.ok(!texts.some((t) => t.includes("omitido")), texts.join("\n"));
});

// The lines of verify's reason written under a box: they start with
// "verify falla: " and continue at the same x, in the wall color.
function reasonLines(texts) {
  const start = texts.findIndex((t) => t.text.startsWith("verify falla: "));
  if (start < 0) return [];
  const { x, color } = texts[start];
  const lines = [];
  for (const t of texts.slice(start)) {
    if (t.x !== x || t.color !== color) break;
    lines.push(t.text);
  }
  return lines;
}

test("live view marks a receipt verify rejects, in the drawing and the list", async () => {
  const state = fixture("cut");
  const bad = state.recent.find((r) => r.verified === false);
  assert.equal(bad.decision, "ALLOW", "the fixture cuts at an allowed call");
  const p = page();
  await p.start(state);
  const texts = drawn(p, "hud");
  const mark = texts.find((t) => t.text === "✕ verify falla");
  assert.ok(mark, texts.map((t) => t.text).join("\n"));
  assert.equal(mark.color, tokens["--wall"]);
  assert.equal(texts.filter((t) => t.text.startsWith("✕ verify falla")).length, 1, "only the bad one");

  p.byId.get("live-list").listeners.get("click")[0]();
  const list = p.text("hud-list");
  assert.ok(list.includes(`✕ verify falla: ${bad.order}`), list);
  assert.equal(list.split("✕ verify falla").length - 1, 1);
});

test("live view writes verify's whole reason, over several lines", async () => {
  const state = fixture("cut");
  const bad = state.recent.find((r) => r.verified === false);
  assert.ok(`verify falla: ${bad.order}`.length * 6 > 650, "the reason is longer than one line");
  const p = page();
  await p.start(state);
  const lines = reasonLines(drawn(p, "hud"));
  assert.ok(lines.length >= 2, lines.join("\n"));
  assert.equal(lines.join(" "), `verify falla: ${bad.order}`, "nothing left out");
  assert.ok(!lines.some((line) => line.endsWith("…")));
  assert.ok(!drawn(p, "hud").some((t) => t.text.includes("detalle del recibo")));
});

test("a reason too long for the drawing says it is cut and where to read it whole", async () => {
  const state = fixture("cut");
  const bad = state.recent.find((r) => r.verified === false);
  const long = Array(8).fill(bad.order).join(" / ");
  bad.order = long;
  state.page.receipts.find((r) => r.evidence_id === bad.evidence_id).order = long;
  const p = page();
  await p.start(state);
  const texts = drawn(p, "hud");
  const lines = reasonLines(texts);
  assert.equal(lines.length, 3);
  assert.ok(lines[2].endsWith("…"), lines[2]);
  const more = texts.find((t) => t.text === "la razón sigue en el detalle del recibo: haz clic en la fila");
  assert.ok(more, texts.map((t) => t.text).join("\n"));
  // A click on that row opens the receipt, where the reason is whole.
  const row = p.hud.rows.findIndex((r) => r.r.evidence_id === bad.evidence_id);
  p.byId.get("hud").listeners.get("click")[0]({ clientY: p.hud.geo.tops[row] + 60 });
  const drawer = p.text("drawer-body");
  assert.ok(drawer.includes(long), drawer.slice(0, 400));
});

// Where a drawn text starts and ends, with the recorder's measure (6 px a
// character) and the alignment it was drawn with.
function extent(t) {
  const w = t.text.length * 6;
  if (t.align === "right" || t.align === "end") return [t.x - w, t.x];
  if (t.align === "center") return [t.x - w / 2, t.x + w / 2];
  return [t.x, t.x + w];
}

test("on a 420 px canvas no live view text leaves the drawing and the long row still opens", async () => {
  const state = fixture("cut");
  const bad = state.recent.find((r) => r.verified === false);
  const long = Array(8).fill(bad.order).join(" / ");
  bad.order = long;
  state.page.receipts.find((r) => r.evidence_id === bad.evidence_id).order = long;
  // A server name longer than the drawing is wide, in the agent label at
  // the top and in every box.
  for (const r of state.recent) r.server = "a-server-whose-name-is-longer-than-a-narrow-window-is-wide";
  const p = page({ width: 420 });
  await p.start(state);
  const texts = drawn(p, "hud");
  assert.ok(texts.length > 10, texts.map((t) => t.text).join("\n"));
  for (const t of texts) {
    const [from, to] = extent(t);
    assert.ok(from >= 0 && to <= 420, `${JSON.stringify(t.text)} spans ${from}..${to}`);
  }
  // The note on where to read the rest is written whole, inside the box
  // (its text column ends 12 px before the box does: 420 - 12 - 12).
  const hint = "la razón sigue en el detalle del recibo: haz clic en la fila";
  const first = texts.findIndex((t) => hint.startsWith(t.text) && t.text.startsWith("la razón"));
  assert.ok(first >= 0, texts.map((t) => t.text).join("\n"));
  const more = [];
  for (const t of texts.slice(first)) {
    if (t.x !== texts[first].x || t.color !== texts[first].color) break;
    more.push(t);
  }
  assert.ok(more.length >= 2, "the note is wrapped at this width");
  assert.equal(more.map((t) => t.text).join(" "), hint);
  for (const t of more) assert.ok(extent(t)[1] <= 420 - 24, `${t.text} ends at ${extent(t)[1]}`);
  // The row holds all its lines: a click on the note's last line opens
  // that receipt, where the reason is whole.
  const row = p.hud.rows.findIndex((r) => r.r.evidence_id === bad.evidence_id);
  const last = more[more.length - 1].y;
  assert.ok(last < p.hud.geo.bottoms[row] - 10, `the note's last line (${last}) is inside the row (${p.hud.geo.bottoms[row]})`);
  p.byId.get("hud").listeners.get("click")[0]({ clientY: last });
  const drawer = p.text("drawer-body");
  assert.ok(drawer.includes(long), drawer.slice(0, 400));
});

test("a healthy home draws no verify mark and the DENY wall says what decided it", async () => {
  const state = fixture("healthy");
  const p = page();
  await p.start(state);
  const texts = drawn(p, "hud");
  assert.ok(!texts.some((t) => t.text.includes("verify falla")));
  const kinds = state.recent.filter((r) => r.decision === "DENY").map((r) => r.decided_by.kind).sort();
  assert.deepEqual(kinds, ["default_deny", "rule"]);
  const wall = texts.filter((t) => t.color === tokens["--wall"]).map((t) => t.text);
  assert.ok(wall.includes("default deny: ninguna regla lo permite"), wall.join("\n"));
  const rule = state.recent.find((r) => r.decided_by.kind === "rule" && r.decision === "DENY").decided_by.rule_id;
  assert.ok(wall.includes(`regla ${rule}`), wall.join("\n"));
  assert.equal(texts.filter((t) => t.text === "BLOQUEADA").length, 2);
  // Home: the server comes from the most recent receipts, and says so.
  const home = p.text("view-home");
  assert.ok(home.includes("fake") && home.includes("de los 40 recibos más recientes"), home);
});

test("a pending call is an unsigned notice, apart from its signed receipt", async () => {
  const state = fixture("pending");
  const held = state.recent.find((r) => r.decision === "REQUIRE_APPROVAL");
  assert.equal(held.verified, true, "the held receipt itself is verified");
  const p = page({ now: pendingNow() });
  await p.start(state);
  // In the drawing, before the wall.
  const texts = drawn(p, "hud");
  const notice = texts.find((t) => t.text === "pendiente · aviso sin firma · verify no lo comprueba");
  assert.ok(notice, texts.map((t) => t.text).join("\n"));
  assert.equal(notice.color, tokens["--ask"]);
  // The card for the notice says it is not signed, with the commands.
  const card = p.text("live-rest");
  assert.ok(card.includes("Sin firma"), card);
  assert.ok(card.includes(state.pending[0].commands.approve), card);
  // On the chain, the mark is the receipt's.
  p.go("#/chain");
  const chain = p.canvas("chain").texts.map((t) => t.text);
  assert.ok(chain.includes("recibo ✓"), chain.join("\n"));
  assert.ok(chain.includes("pendiente · aviso sin firma · verify no lo comprueba"));
});

// Every node under `root` whose own text is `text`.
function nodesWithText(root, text) {
  return root.all().filter((n) => n.children.length === 1 && n.textContent === text);
}

test("the approval card shows and copies the server's commands unchanged", async () => {
  const state = fixture("pending");
  const { approve, reject } = state.pending[0].commands;
  // As the server writes them: absolute binary and --dir, quoted only
  // when a POSIX shell would interpret the path.
  assert.ok(approve.startsWith("/home/user/.local/bin/praetore-mcp approve "), approve);
  assert.ok(approve.endsWith(" --dir /home/user/.praetore/mcp"), approve);
  const p = page({ now: pendingNow() });
  await p.start(state);
  const root = p.byId.get("live-rest");
  const shown = root.all().find((n) => n.tagName === "PRE" && n.textContent.includes(" approve "));
  assert.ok(shown, p.text("live-rest"));
  assert.equal(shown.textContent, `${approve}\n${reject}`);
  const [button] = nodesWithText(root, "Copiar comando para aprobar");
  assert.ok(button, p.text("live-rest"));
  await button.listeners.get("click")[0]();
  assert.deepEqual(p.copied, [approve]);
  assert.equal(p.copied[0], shown.textContent.split("\n")[0], "copied = first line shown");
});

test("the approval card says when it expires in local time, with UTC and what is left", async () => {
  const state = fixture("pending");
  const expires = state.pending[0].expires_at;
  const p = page({ now: Date.parse(expires) - (9 * 60 + 40) * 1000 });
  await p.start(state);
  const card = p.text("live-rest");
  const utc = `${expires.slice(0, 19).replace("T", " ")} UTC`;
  const local = new Date(expires).toLocaleString("es", {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
  assert.ok(card.includes(`Vence a las ${local} (hora local) / ${utc}`), card);
  assert.ok(card.includes("Vence en 9 min 40 s"), card);
});

test("an approval that expired unused is marked expired, apart from approved and executed", async () => {
  const state = fixture("pending");
  const asked = state.recent.filter((r) => r.decision === "REQUIRE_APPROVAL");
  assert.ok(asked.length >= 1);
  const expired = structuredClone(asked[0]);
  expired.evidence_id = "00000000-0000-4000-8000-000000000001";
  expired.approval = "approve by 0123456789abcdef, expired unused";
  const executed = structuredClone(asked[0]);
  executed.evidence_id = "00000000-0000-4000-8000-000000000002";
  executed.approval = "approve by 0123456789abcdef, executed once";
  const live = structuredClone(asked[0]);
  live.evidence_id = "00000000-0000-4000-8000-000000000003";
  live.approval = "approve by 0123456789abcdef";
  state.approval_history = [expired, executed, live];
  const p = page({ now: pendingNow(), hash: "#/info/approvals" });
  await p.start(state);
  const history = p.byId.get("info-approvals");
  const tags = history.all().filter((n) => n.tagName === "SPAN" && n.className.startsWith("tag "));
  const texts = tags.map((n) => [n.textContent, n.className]);
  assert.deepEqual(texts, [
    ["Vencida: se aprobó pero no se ejecutó a tiempo", "tag bad"],
    ["Aprobada y ejecutada", "tag ok"],
    ["Aprobada", "tag ok"],
  ]);
});

test("an unreadable journal is said to be unreadable, not empty", async () => {
  const state = fixture("unreadable");
  assert.equal(state.verify.status, "error");
  const p = page({ hash: "#/home" });
  await p.start(state);
  const home = p.text("view-home");
  assert.ok(home.includes("No se pudo leer el journal."), home);
  assert.ok(!home.includes("Todavía no hay recibos"), home);
  assert.ok(home.includes(state.verify.error), home);
  p.go("#/live");
  const texts = drawn(p, "hud").map((t) => t.text);
  assert.ok(texts.includes("No se pudo leer el journal."), texts.join("\n"));
});

test("with reduced motion no frame is requested, even when a receipt arrives", async () => {
  const p = page({ reduced: true, now: pendingNow() });
  await p.start(fixture("healthy"));
  await p.poll(fixture("pending"));
  assert.equal(p.requestedSince(), 0, "frames requested with reduced motion");
  // The picture is still drawn, complete.
  const texts = p.canvas("hud").texts.map((t) => t.text);
  assert.ok(texts.includes("PIDIÓ APROBACIÓN"), texts.join("\n"));
});

test("no sweep or scan on the first load nor on a poll that changed nothing", async () => {
  const p = page();
  await p.start(fixture("healthy"));
  // First load: one still picture, nothing scanned in, no sweep.
  assert.equal(p.hud.readAt, null);
  assert.ok(p.hud.rows.every((row) => row.born === null));
  assert.equal(p.runFrames(), 1, "one frame for the still picture");
  p.requestedSince();
  // Same answer: nothing is drawn again.
  await p.poll(fixture("healthy"));
  await p.poll(fixture("healthy"));
  assert.equal(p.requestedSince(), 0, "a poll with no change asked for frames");
  assert.equal(p.hud.readAt, null);
});

test("a new receipt is scanned in and the sweep runs once", async () => {
  const p = page({ now: pendingNow() });
  await p.start(fixture("healthy"));
  p.runFrames();
  p.requestedSince();
  await p.poll(fixture("pending"));
  assert.notEqual(p.hud.readAt, null, "a change starts the sweep");
  const newest = p.hud.rows[0];
  assert.equal(newest.r.decision, "REQUIRE_APPROVAL");
  assert.notEqual(newest.born, null, "the new receipt is scanned in");
  assert.ok(p.hud.rows.slice(1).every((row) => row.born === null), "only the new one");
  const frames = p.runFrames();
  assert.ok(frames > 10 && frames < 200, `${frames} frames, then the page is still`);
  assert.equal(p.frames.length, 0);
});

// ---------- sessions ----------

// The article nodes of the Sessions view, one per report written at close.
function sessionCards(p) {
  return p.byId.get("sessions-list").all().filter((n) => n.getAttribute("data-session-id") !== null);
}

function links(root) {
  return root.all().filter((n) => n.tagName === "A").map((n) => ({
    href: n.getAttribute("href"), download: n.getAttribute("download"), text: n.textContent,
  }));
}

test("the sessions view lists each close report with its regenerations grouped apart", async () => {
  const state = fixture("sessions");
  const items = state.reports.items;
  assert.equal(items.length, 2);
  const withRegen = items.find((i) => i.regenerations.length === 1);
  assert.ok(withRegen, JSON.stringify(items.map((i) => i.stem)));
  const regen = withRegen.regenerations[0];
  assert.match(regen.json.name, /^session-\d{8}T\d{6}Z-[0-9a-f]{8}\.regen-\d{8}T\d{6}Z\.json$/);

  const p = page({ hash: "#/sessions" });
  await p.start(state);
  const cards = sessionCards(p);
  // One card per close report; the regeneration is not a card of its own.
  assert.deepEqual(cards.map((c) => c.getAttribute("data-session-id")), items.map((i) => i.session_id));
  const card = cards.find((c) => c.getAttribute("data-session-id") === withRegen.session_id);
  const regenBox = card.all().find((n) => n.className === "session-regens");
  assert.ok(regenBox, "regenerations are grouped under their close report");
  const regenRows = regenBox.all().filter((n) => n.getAttribute("data-regenerated-at") !== null);
  assert.deepEqual(regenRows.map((n) => n.getAttribute("data-regenerated-at")), [regen.regenerated_at]);
  assert.ok(regenBox.textContent.includes("1 regeneración (praetore-mcp report), aparte del original"));

  // The close report's own buttons name the close files; the regeneration's
  // name its own pair, and only inside the group.
  const regenLinks = links(regenBox);
  const ownLinks = links(card).filter((l) => !regenLinks.some((r) => r.href === l.href));
  assert.deepEqual(ownLinks.map((l) => [l.text, l.href, l.download]), [
    ["Descargar PDF", `/reports/${withRegen.pdf.name}`, withRegen.pdf.name],
    ["Descargar JSON", `/reports/${withRegen.json.name}`, withRegen.json.name],
  ]);
  assert.deepEqual(regenLinks.map((l) => [l.text, l.href]), [
    ["Descargar PDF", `/reports/${regen.pdf.name}`],
    ["Descargar JSON", `/reports/${regen.json.name}`],
  ]);
  // The SHA-256 of each JSON is shown next to its button.
  assert.ok(card.textContent.includes(withRegen.json.sha256));
  assert.ok(regenBox.textContent.includes(regen.json.sha256));
  // The other session has no regeneration group.
  const other = cards.find((c) => c !== card);
  assert.ok(!other.all().some((n) => n.className === "session-regens"));
  // Agent, server, mode, open and close in local time and UTC, verify.
  const h = withRegen.header;
  for (const text of [h.agent, h.server, h.mode, `${h.started_at.slice(0, 19).replace("T", " ")} UTC`,
    `${h.ended_at.slice(0, 19).replace("T", " ")} UTC`, "verify UNANCHORED", h.praetore_mcp_version]) {
    assert.ok(card.textContent.includes(text), text);
  }
  // What a report is, said once on the view.
  assert.ok(p.text("sessions-list").includes("no firma nada y no prueba que una persona lo revisó"));
});

// The chip of each report, read from verify.assurance (the label of
// receipts::Assurance that the report records), in every language.
function chips(p) {
  return p.byId.get("sessions-list").all().filter((n) => n.getAttribute("data-assurance") !== null)
    .map((n) => [n.getAttribute("data-assurance"), n.className, n.textContent]);
}

test("the session chip shows OK, UNANCHORED or FAIL from verify's assurance, never 'passed'", async () => {
  const base = fixture("sessions");
  // The fixture's reports were written with no head given. The cases below
  // set the level, or take it out for a report from before it existed:
  // "passed" alone may have had no heads, so it is not OK.
  assert.equal(base.reports.items[0].header.verify.assurance, "UNANCHORED");
  assert.equal(base.reports.items[0].header.verify.result, "passed");
  const U = "UNANCHORED", warn = "chip warn";
  const unanchored = { es: "verify UNANCHORED · faltan heads, no es OK", en: "verify UNANCHORED · heads missing, not OK",
    pt: "verify UNANCHORED · faltam heads, não é OK" };
  const cases = [
    [{ result: "passed", assurance: "OK" }, () => ["OK", "chip ok", "verify OK"]],
    [{ result: "passed", assurance: U }, (lang) => [U, warn, unanchored[lang]]],
    [{ result: "failed", assurance: "FAIL" }, () => ["FAIL", "chip bad", "verify FAIL"]],
    // Without the level: never OK.
    [{ result: "passed" }, (lang) => [U, warn, unanchored[lang]]],
    [{ result: "something else" }, (lang) => [U, warn, unanchored[lang]]],
    [{ result: "failed" }, () => ["FAIL", "chip bad", "verify FAIL"]],
    // A value the page does not know is not a pass.
    [{ result: "passed", assurance: "ok" }, () => ["FAIL", "chip bad", "verify FAIL"]],
    [{ result: "passed", assurance: "toString" }, () => ["FAIL", "chip bad", "verify FAIL"]],
    [{ result: "passed", assurance: true }, () => ["FAIL", "chip bad", "verify FAIL"]],
  ];
  for (const lang of ["es", "en", "pt"]) {
    for (const [verify, want] of cases) {
      const state = structuredClone(base);
      for (const item of state.reports.items) {
        item.header.verify = { ...item.header.verify, ...verify };
        if (!("assurance" in verify)) delete item.header.verify.assurance;
        for (const regen of item.regenerations) regen.header.verify = structuredClone(item.header.verify);
      }
      const p = page({ hash: "#/sessions" });
      p.run(`localStorage.setItem("praetore-mcp-dashboard-lang", ${JSON.stringify(lang)})`);
      await p.start(state);
      assert.equal(p.run("document.documentElement.lang"), lang);
      const got = chips(p);
      // Two close reports and one regeneration, each with its chip.
      assert.equal(got.length, 3, `${lang} ${JSON.stringify(verify)}`);
      for (const chip of got) assert.deepEqual(chip, want(lang), `${lang} ${JSON.stringify(verify)}`);
      assert.ok(!p.text("sessions-list").match(/verify (passed|pasó|passou)/), lang);
      // "Approval" is the human approval on this page; a verify chip never says it.
      for (const chip of got) assert.ok(!/aprobaci|approv|aprova/i.test(chip[2]), `${lang} ${chip[2]}`);
    }
  }
});

test("decisions and approval statuses are two rows on fixed columns, zeros shown", async () => {
  const p = page({ hash: "#/sessions" });
  await p.start(fixture("sessions"));
  const card = sessionCards(p)[0];
  const rows = card.all().filter((n) => n.className === "session-counts");
  assert.equal(rows.length, 2);
  const labels = (row) => row.all().filter((n) => (n.className || "").split(" ")[0] === "session-cell")
    .map((n) => n.children[0].textContent);
  assert.deepEqual(labels(rows[0]), ["ALLOW", "DENY", "HELD", "FORWARDED", "WOULD ASK"]);
  assert.deepEqual(labels(rows[1]), ["APPROVED", "REJECTED", "PENDING", "EXPIRED"]);
  assert.ok(rows[1].textContent.startsWith("Estado de las aprobaciones (de las llamadas retenidas; no son más llamadas)"));
  // Every column has a number, 0 included.
  const values = rows.flatMap((row) => row.all().filter((n) => n.tagName === "STRONG").map((n) => n.textContent));
  assert.equal(values.length, 9);
  assert.ok(values.includes("0"), values.join(","));
});

test("a new close report shows 'report ready' with its download on the next refresh", async () => {
  const before = fixture("healthy");
  const after = fixture("pending");
  assert.equal(after.reports.items.length, before.reports.items.length + 1);
  const added = after.reports.items.find((i) => !before.reports.items.some((b) => b.stem === i.stem));
  const p = page({ now: pendingNow() });
  await p.start(before);
  // The toasts box exists once the page has written a toast in it.
  const ready = () => (p.byId.has("toasts") ? p.byId.get("toasts").all() : [])
    .filter((n) => (n.className || "").includes("report-ready"));
  assert.equal(ready().length, 0, "nothing on the first load");
  await p.poll(after);
  assert.equal(ready().length, 1);
  assert.ok(ready()[0].textContent.includes(`Informe listo · sesión ${added.session_id}`));
  assert.deepEqual(links(ready()[0]).map((l) => [l.href, l.download]), [[`/reports/${added.pdf.name}`, added.pdf.name]]);
  // A regeneration is not a new session: no second notice.
  await p.poll(fixture("sessions"));
  assert.equal(ready().length, 1);
});

test("#/sessions/<id> opens the Sessions view on that session", async () => {
  const state = fixture("sessions");
  const id = state.reports.items[1].session_id;
  const p = page({ hash: `#/sessions/${id}` });
  await p.start(state);
  assert.equal(p.byId.get("view-sessions").hidden, false);
  const focused = sessionCards(p).filter((c) => c.className.includes("focus"));
  assert.deepEqual(focused.map((c) => c.getAttribute("data-session-id")), [id]);
  // An id that is not 8 hex characters is not a session link.
  const q = page({ hash: "#/sessions/../x" });
  await q.start(state);
  assert.ok(!sessionCards(q).some((c) => c.className.includes("focus")));
});

// ---------- approval history and live caption ----------

function localEs(iso) {
  return new Date(iso).toLocaleString("es", {
    year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit",
  });
}

test("an approved call shows when the person decided it, not when it was held", async () => {
  const state = fixture("pending");
  const held = state.approval_history[0];
  assert.equal(held.approval_decided_at, null, "the server sends the field, null before a decision");
  // The same call after a person approved it, 7 minutes after the receipt.
  const approved = structuredClone(state);
  const row = approved.approval_history[0];
  const decidedAt = new Date(Date.parse(row.decided_at) + 7 * 60_000).toISOString().replace(/\.\d+Z$/, "Z");
  row.approval = "approve by 0123456789abcdef, executed once";
  row.approval_decided_at = decidedAt;
  approved.pending = [];
  const p = page({ hash: "#/info/approvals", now: pendingNow() });
  await p.start(approved);
  const text = p.text("info-approvals");
  assert.ok(text.includes(`${decidedAt.slice(0, 19).replace("T", " ")} UTC`), text);
  assert.ok(!text.includes(`${row.decided_at.slice(0, 19).replace("T", " ")} UTC`), "the held receipt's time is not shown");
  assert.ok(text.includes("hora de la decisión humana"), text);
  // Before a decision: the time it was held, said so.
  const q = page({ hash: "#/info/approvals", now: pendingNow() });
  await q.start(state);
  const before = q.text("info-approvals");
  assert.ok(before.includes(`${held.decided_at.slice(0, 19).replace("T", " ")} UTC`), before);
  assert.ok(before.includes("hora en que se retuvo"), before);
});

test("the live caption says how many rows it shows and from when, in each view", async () => {
  // Twelve decisions in the last 15 minutes: more than the drawing shows.
  const base = fixture("healthy");
  const now = Date.parse("2026-01-01T00:00:00Z");
  const sample = base.recent.find((r) => !r.parse_error);
  const recent = Array.from({ length: 12 }, (_, i) => {
    const r = structuredClone(sample);
    r.evidence_id = `00000000-0000-4000-8000-${String(i).padStart(12, "0")}`;
    r.decided_at = new Date(now - (i + 1) * 30_000).toISOString().replace(/\.\d+Z$/, "Z");
    return r;
  });
  const state = { ...structuredClone(base), recent, summary: { ...base.summary, total: 12 } };
  const p = page({ hash: "#/live", now });
  await p.start(state);
  let caption = p.text("live-caption");
  assert.ok(caption.startsWith("12 decisiones en los últimos 15 minutos."), caption);
  assert.ok(caption.endsWith(`Se muestran las 8 más recientes, desde ${localEs(recent[7].decided_at)}.`), caption);
  // The list view shows all twelve and says so.
  p.byId.get("live-list").listeners.get("click")[0]();
  caption = p.text("live-caption");
  assert.ok(caption.endsWith(`Se muestran las 12 más recientes, desde ${localEs(recent[11].decided_at)}.`), caption);
});

test("the live list shows when the person decided an approved call, not when it was held", async () => {
  const state = fixture("pending");
  const held = state.recent.find((r) => r.decision === "REQUIRE_APPROVAL");
  assert.ok(held, "the pending fixture has a held call in recent");
  assert.equal(held.approval_decided_at, null, "the server sends the field, null before a decision");
  const approved = structuredClone(state);
  const row = approved.recent.find((r) => r.evidence_id === held.evidence_id);
  const decidedAt = new Date(Date.parse(row.decided_at) + 7 * 60_000).toISOString().replace(/\.\d+Z$/, "Z");
  row.approval = "approve by 0123456789abcdef, executed once";
  row.approval_decided_at = decidedAt;
  approved.pending = [];
  const p = page({ hash: "#/live", now: pendingNow() });
  await p.start(approved);
  p.byId.get("live-list").listeners.get("click")[0]();
  const text = p.text("hud-list");
  assert.ok(text.includes(`${decidedAt.slice(0, 19).replace("T", " ")} UTC`), text);
  assert.ok(!text.includes(`${held.decided_at.slice(0, 19).replace("T", " ")} UTC`), "the held receipt's time is not shown");
  assert.ok(text.includes("hora de la decisión humana"), text);
  // Before a decision: the time it was held, said so.
  const q = page({ hash: "#/live", now: pendingNow() });
  await q.start(state);
  q.byId.get("live-list").listeners.get("click")[0]();
  const before = q.text("hud-list");
  assert.ok(before.includes(`${held.decided_at.slice(0, 19).replace("T", " ")} UTC`), before);
  assert.ok(before.includes("hora en que se retuvo"), before);
});

test("an approval that expired undecided reads Expired in the visual and the list, and nothing is left to decide", async () => {
  const state = fixture("pending");
  const held = state.recent.find((r) => r.decision === "REQUIRE_APPROVAL");
  assert.equal(held.approval, "pending");
  // What the server sends once expires_at has passed: the label on every
  // copy of the receipt, and no call left to decide.
  const expired = structuredClone(state);
  for (const list of [expired.recent, expired.approval_history, expired.page.receipts]) {
    for (const r of list) if (r.evidence_id === held.evidence_id) r.approval = "expired";
  }
  expired.pending = [];
  const p = page({ hash: "#/live", now: pendingNow() });
  await p.start(expired);
  const texts = drawn(p, "hud").map((t) => t.text);
  assert.ok(texts.includes("Vencida"), texts.join(" | "));
  assert.ok(!texts.some((t) => t.includes("Esperando decisión") || t.startsWith("pendiente")), texts.join(" | "));
  assert.ok(p.text("live-rest").includes("Nada por decidir"), p.text("live-rest"));
  p.byId.get("live-list").listeners.get("click")[0]();
  const list = p.text("hud-list");
  assert.ok(list.includes("Vencida"), list);
  assert.ok(!list.includes("Esperando decisión") && !list.includes("pendiente ·"), list);
  // The approval history and the drawer say the same.
  const q = page({ hash: "#/info/approvals", now: pendingNow() });
  await q.start(expired);
  assert.ok(q.text("info-approvals").includes("Vencida"), q.text("info-approvals"));
  // The same label in English and Portuguese, picked with the selector.
  for (const [code, label] of [["en", "Expired"], ["pt", "Vencida"]]) {
    const select = p.byId.get("lang");
    select.value = code;
    select.listeners.get("change")[0]();
    assert.ok(p.text("hud-list").includes(label), `${code}: ${p.text("hud-list")}`);
  }
});

// m5: a path or a name may hold a terminal escape, \r or \n. The page and
// both drawings show them as \u{..}, never raw: page text, titles, <pre>
// blocks, the canvas texts cut to fit (clipText) and wrapped (wrapText).
async function controlCharsShown(name) {
  const evil = "x\u001b[2K\r\nfake\u009b";
  const escaped = "x\\u{1b}[2K\\u{d}\\u{a}fake\\u{9b}";
  const state = fixture(name);
  state.home = `/home/user/${evil}`;
  state.policy.path = `/home/user/${evil}/policy.json`;
  for (const r of [...state.recent, ...state.page.receipts]) {
    r.server = evil;
    r.tool = `t${evil}`;
    if (r.arguments && typeof r.arguments === "object") r.arguments.from = `/srv/${evil}`;
    if (typeof r.order === "string") r.order = `${r.order} ${evil}`;
  }
  for (const held of state.pending || []) {
    held.server = evil;
    held.tool = `t${evil}`;
    // Canonical JSON escapes C0 itself; C1 and bidi stay raw in it.
    held.arguments_canonical = `{"from":"/srv/x\u009b‮"}`;
  }
  const p = page({ now: pendingNow() });
  await p.start(state);
  const roots = () => [...p.byId.values(), p.tbody];
  const texts = [];
  const drawings = [];
  for (const view of ["#/home", "#/live", "#/chain", "#/info", "#/live"]) {
    p.go(view);
    drawings.push(...drawn(p, "hud"), ...drawn(p, "chain"));
    for (const node of roots()) {
      texts.push(node.textContent);
      for (const n of node.all()) if (n.getAttribute("title") !== null) texts.push(n.getAttribute("title"));
    }
  }
  const text = texts.join("\n");
  assert.ok(!/[\u001b\r\u009b‮]/.test(text), `${name}: raw control in the page`);
  assert.ok(!text.includes("[2K\n"), `${name}: raw newline from a name in the page`);
  assert.ok(text.includes(escaped), `${name}: the escaped name is in the page`);
  const drawnText = drawings.map((t) => t.text);
  for (const t of drawnText) assert.ok(!/[\u0000-\u001f\u007f-\u009f]/.test(t), `${name}: raw control drawn: ${JSON.stringify(t)}`);
  assert.ok(drawnText.some((t) => t.includes("\\u{1b}[2K")), drawnText.join("\n"));
  return { text, drawnText };
}

test("paths and names with control characters are shown escaped in the page and the drawings", async () => {
  const pending = await controlCharsShown("pending");
  assert.ok(pending.text.includes("\\u{9b}\\u{202e}"), "the canonical arguments <pre>");
  const cut = await controlCharsShown("cut");
  // The verify reason of the cut receipt is wrapped over several lines.
  assert.ok(cut.drawnText.some((t) => t.includes("fake\\u{9b}")), cut.drawnText.join("\n"));
});

// m1: shown() escapes exactly the code points praetore_core does
// (fixtures/invisible-ranges.json, held equal to
// praetore_core::display::is_invisible by tests/control_chars.rs).
test("shown() escapes exactly the code points of praetore_core", () => {
  const { ranges } = fixture("invisible-ranges");
  const p = page();
  const differ = [];
  let k = 0;
  for (let cp = 0; cp <= 0x10ffff; cp += 1) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    while (k < ranges.length && ranges[k][1] < cp) k += 1;
    const core = k < ranges.length && ranges[k][0] <= cp;
    const page_ = p.shown(String.fromCodePoint(cp)) !== String.fromCodePoint(cp);
    if (core !== page_) differ.push(cp.toString(16).toUpperCase().padStart(4, "0"));
  }
  assert.deepEqual(differ, [], `${differ.length} code points differ: U+${differ.join(" U+")}`);
});

// m1: Intl can write U+00A0 or U+202F inside dates and times (browsers do
// in "12:30 PM"). Those are invisible for praetore_core, so the page turns
// them into plain spaces before shown(): its own dates never show \u{..}.
test("dates the page formats with Intl never show escaped spaces", async () => {
  const p = page({ now: pendingNow() });
  p.run(`{
    const real = Date.prototype.toLocaleString;
    Date.prototype.toLocaleString = function (...a) { return real.apply(this, a).replace(/ /g, "\u202f").replace(",", ",\u00a0"); };
  }`);
  await p.start(fixture("pending"));
  const card = p.text("live-rest");
  assert.ok(/\d\d:\d\d/.test(card), card);
  assert.ok(!card.includes("\\u{202f}") && !card.includes("\\u{a0}"), card);
});

// B1: the checks list does not promise one use without the condition it
// needs: both journals cut at the end let an approval run again, and only
// the saved heads show it. Same text in Spanish, English and Portuguese.
test("the integrity checks list says when one use per approval does not hold", async () => {
  const p = page({ hash: "#/info/integrity" });
  await p.start(fixture("healthy"));
  for (const [code, words] of [
    ["es", ["un uso por aprobación", "se recortan ambos del final de los journals", "pasa los dos heads guardados"]],
    ["en", ["one use per approval", "are both cut from the end of the journals can run again", "pass both saved heads to detect it"]],
    ["pt", ["um uso por aprovação", "são ambos cortados do fim dos journals", "passe os dois heads guardados"]],
  ]) {
    if (code !== "es") {
      const select = p.byId.get("lang");
      select.value = code;
      select.listeners.get("change")[0]();
    }
    const text = p.text("info-integrity");
    for (const w of words) assert.ok(text.includes(w), `${code}: ${w}\n${text}`);
    assert.ok(!/single use|uso único/.test(text), `${code}: ${text}`);
  }
});

// What the page writes for each effect a DENY can have, per language.
const DENY_WORDS = {
  es: { blocked: "Bloqueadas", sub: (n) => `+ ${n} denegadas en observe, no bloqueadas`, hudBlocked: "BLOQUEADA",
    hudRan: "DENEGADA · NO BLOQUEADA", tagBlocked: "Bloqueada", tagRan: "Denegada · no bloqueada", note: "observe: registrada, no aplicada" },
  en: { blocked: "Blocked", sub: (n) => `+ ${n} denied in observe, not blocked`, hudBlocked: "BLOCKED",
    hudRan: "DENIED · NOT BLOCKED", tagBlocked: "Blocked", tagRan: "Denied · not blocked", note: "observe: recorded, not applied" },
  pt: { blocked: "Bloqueadas", sub: (n) => `+ ${n} negadas em observe, não bloqueadas`, hudBlocked: "BLOQUEADA",
    hudRan: "NEGADA · NÃO BLOQUEADA", tagBlocked: "Bloqueada", tagRan: "Negada · não bloqueada", note: "observe: registrada, não aplicada" },
};

async function pageIn(lang, state) {
  const p = page();
  p.run(`localStorage.setItem("praetore-mcp-dashboard-lang", ${JSON.stringify(lang)})`);
  await p.start(state);
  assert.equal(p.run("document.documentElement.lang"), lang);
  return p;
}

const count = (text, part) => text.split(part).length - 1;

test("a DENY that observe forwarded is never counted, drawn or listed as blocked", async () => {
  const state = fixture("observe");
  // The real session: two DENYs the wrapped server ran, and the DENY of a
  // call the policy does not classify, which observe refused.
  assert.deepEqual(state.recent.map((r) => [r.tool, r.mode, r.decision, r.deny_effect]), [
    ["safety_stop", "observe", "DENY", "blocked"],
    ["echo", "observe", "DENY", "not_applied"],
    ["delete_file", "observe", "DENY", "not_applied"],
  ]);
  assert.deepEqual([state.summary.deny, state.summary.blocked, state.summary.deny_not_applied], [3, 1, 2]);
  for (const [lang, w] of Object.entries(DENY_WORDS)) {
    const p = await pageIn(lang, state);
    const home = p.text("view-home");
    assert.ok(home.includes(`${w.blocked}1${w.sub(2)}`), `${lang}: ${home}`);
    const texts = drawn(p, "hud").map((t) => t.text);
    assert.equal(texts.filter((t) => t === w.hudBlocked).length, 1, `${lang}: ${texts.join("\n")}`);
    assert.equal(texts.filter((t) => t === w.hudRan).length, 2, `${lang}: ${texts.join("\n")}`);
    // The observe note comes first on its line, so clipping cannot cut it,
    // and it is not written on the DENY observe did apply.
    assert.equal(texts.filter((t) => t.startsWith(w.note)).length, 2, `${lang}: ${texts.join("\n")}`);
    assert.equal(texts.filter((t) => t.includes(w.note)).length, 2, `${lang}: ${texts.join("\n")}`);
    p.byId.get("live-list").listeners.get("click")[0]();
    const list = p.text("hud-list");
    assert.equal(count(list, w.tagRan), 2, `${lang}: ${list}`);
    assert.equal(count(list, w.tagBlocked), 1, `${lang}: ${list}`);
  }
});

test("in enforce every DENY is blocked and the home has no observe line", async () => {
  const state = fixture("healthy");
  assert.ok(state.recent.every((r) => r.mode === "enforce"));
  assert.deepEqual(state.recent.filter((r) => r.decision === "DENY").map((r) => r.deny_effect), ["blocked", "blocked"]);
  assert.deepEqual([state.summary.deny, state.summary.blocked, state.summary.deny_not_applied], [2, 2, 0]);
  for (const [lang, w] of Object.entries(DENY_WORDS)) {
    const p = await pageIn(lang, state);
    const home = p.text("view-home");
    assert.ok(home.includes(`${w.blocked}2`), `${lang}: ${home}`);
    assert.ok(!home.includes("observe"), `${lang}: ${home}`);
    const texts = drawn(p, "hud").map((t) => t.text);
    assert.equal(texts.filter((t) => t === w.hudBlocked).length, 2, `${lang}: ${texts.join("\n")}`);
    assert.equal(texts.filter((t) => t === w.hudRan).length, 0, `${lang}: ${texts.join("\n")}`);
  }
});

test("a DENY whose effect the receipt does not say is shown as the decision, not as blocked", async () => {
  const state = fixture("healthy");
  for (const r of state.recent) if (r.decision === "DENY") r.deny_effect = null;
  const p = await pageIn("es", state);
  const texts = drawn(p, "hud").map((t) => t.text);
  assert.equal(texts.filter((t) => t === "DENEGADA").length, 2, texts.join("\n"));
  assert.equal(texts.filter((t) => t === "BLOQUEADA").length, 0, texts.join("\n"));
  p.byId.get("live-list").listeners.get("click")[0]();
  assert.equal(count(p.text("hud-list"), "Denegada"), 2, p.text("hud-list"));
  assert.equal(count(p.text("hud-list"), "Bloqueada"), 0, p.text("hud-list"));
});
