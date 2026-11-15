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
  getBoundingClientRect() { return { width: 1200, height: 600, top: 0, left: 0 }; }
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
    fillText(text, x, y) { ctx.texts.push({ text: String(text), color: ctx.fillStyle, x, y }); },
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
// the clock and the frames are driven by the test.
function page({ reduced = false, hash = "#/live", now = Date.parse("2026-01-01T00:00:00Z") } = {}) {
  const byId = new Map();
  const getElementById = (id) => {
    if (!byId.has(id)) {
      const node = new Node(id === "hud" || id === "chain" ? "canvas" : "div");
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
  const context = {
    console,
    Node,
    document,
    location: { hash },
    history: { replaceState() {} },
    navigator: { language: "es", clipboard: { writeText: async () => {} } },
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
  hud, chain, load,
};`, context, { filename: "app.js" });
  const p = context.__page;
  let requested = 0;
  return {
    byId,
    frames,
    clock,
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

test("live view marks a receipt verify rejects, in the drawing and the list", async () => {
  const state = fixture("cut");
  const bad = state.recent.find((r) => r.verified === false);
  assert.equal(bad.decision, "ALLOW", "the fixture cuts at an allowed call");
  const p = page();
  await p.start(state);
  const texts = drawn(p, "hud");
  const mark = texts.find((t) => t.text.startsWith("✕ verify falla: "));
  assert.ok(mark, texts.map((t) => t.text).join("\n"));
  assert.ok(bad.order.startsWith(mark.text.slice("✕ verify falla: ".length).replace(/…$/, "")));
  assert.equal(mark.color, tokens["--wall"]);
  assert.equal(texts.filter((t) => t.text.startsWith("✕ verify falla")).length, 1, "only the bad one");

  p.byId.get("live-list").listeners.get("click")[0]();
  const list = p.text("hud-list");
  assert.ok(list.includes(`✕ verify falla: ${bad.order}`), list);
  assert.equal(list.split("✕ verify falla").length - 1, 1);
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
  assert.ok(card.includes(state.pending[0].approval_id.slice(0, 12)) || card.includes("praetore-mcp approve"), card);
  // On the chain, the mark is the receipt's.
  p.go("#/chain");
  const chain = p.canvas("chain").texts.map((t) => t.text);
  assert.ok(chain.includes("recibo ✓"), chain.join("\n"));
  assert.ok(chain.includes("pendiente · aviso sin firma · verify no lo comprueba"));
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
