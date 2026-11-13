// The page itself, on a minimal stand-in DOM (no npm packages): the route of
// each action is chosen by code in every language, the reject confirmation
// says it is final, and a change of language cancels an open confirmation.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const raiz = new URL("../ui/", import.meta.url);
const html = readFileSync(new URL("index.html", raiz), "utf8");
const catalogos = Object.fromEntries(
  ["es", "en", "pt"].map((idioma) => [
    idioma,
    JSON.parse(readFileSync(new URL("i18n/" + idioma + ".json", raiz), "utf8")),
  ]),
);

class Nodo {
  constructor(etiqueta) {
    this.tagName = etiqueta.toUpperCase();
    this.hijos = [];
    this.padre = null;
    this.texto = "";
    this.atributos = new Map();
    this.oyentes = new Map();
    this.disabled = false;
    this.hidden = false;
    this.value = "";
    this.className = "";
    const clases = new Set();
    this.classList = {
      add: (c) => clases.add(c),
      remove: (c) => clases.delete(c),
      contains: (c) => clases.has(c),
    };
  }
  get textContent() {
    return this.hijos.length ? this.hijos.map((hijo) => hijo.textContent).join("") : this.texto;
  }
  set textContent(valor) {
    this.hijos = [];
    this.texto = String(valor);
  }
  set innerHTML(_valor) {
    throw new Error("innerHTML is never used");
  }
  append(...nodos) {
    for (const nodo of nodos) {
      const hijo = typeof nodo === "string" ? texto(nodo) : nodo;
      hijo.padre = this;
      this.hijos.push(hijo);
    }
  }
  replaceChildren(...nodos) {
    this.hijos = [];
    this.texto = "";
    this.append(...nodos);
  }
  remove() {
    if (this.padre) this.padre.hijos = this.padre.hijos.filter((hijo) => hijo !== this);
  }
  setAttribute(nombre, valor) {
    this.atributos.set(nombre, String(valor));
  }
  getAttribute(nombre) {
    return this.atributos.has(nombre) ? this.atributos.get(nombre) : null;
  }
  addEventListener(tipo, oyente) {
    if (!this.oyentes.has(tipo)) this.oyentes.set(tipo, []);
    this.oyentes.get(tipo).push(oyente);
  }
  disparar(tipo) {
    for (const oyente of this.oyentes.get(tipo) || []) oyente({ target: this, preventDefault() {} });
  }
  click() {
    if (!this.disabled) this.disparar("click");
  }
  scrollIntoView() {}
  *todos() {
    for (const hijo of this.hijos) {
      yield hijo;
      yield* hijo.todos();
    }
  }
  querySelectorAll(selector) {
    const coincide =
      selector === "[data-i18n]"
        ? (nodo) => nodo.getAttribute("data-i18n") !== null
        : (nodo) => nodo.tagName === selector.toUpperCase();
    return [...this.todos()].filter(coincide);
  }
}

function texto(valor) {
  const nodo = new Nodo("#text");
  nodo.texto = valor;
  return nodo;
}

// The page's elements with an id or a data-i18n key, with their initial text.
function documentoDePagina() {
  const html_ = new Nodo("html");
  const body = new Nodo("body");
  html_.append(body);
  const porId = new Map();
  const patron = /<(\w+)([^>]*)>([^<]*)/g;
  for (const [, etiqueta, atributos, contenido] of html.matchAll(patron)) {
    const id = /\bid="([^"]+)"/.exec(atributos);
    const clave = /\bdata-i18n="([^"]+)"/.exec(atributos);
    if (!id && !clave) continue;
    const nodo = new Nodo(etiqueta);
    if (id) porId.set(id[1], nodo);
    if (clave) nodo.setAttribute("data-i18n", clave[1]);
    nodo.texto = contenido;
    body.append(nodo);
  }
  return {
    documentElement: html_,
    body,
    getElementById: (id) => porId.get(id) || null,
    createElement: (etiqueta) => new Nodo(etiqueta),
    createTextNode: texto,
    querySelectorAll: (selector) => html_.querySelectorAll(selector),
  };
}

function almacen(inicial) {
  const datos = new Map(Object.entries(inicial));
  return {
    getItem: (clave) => (datos.has(clave) ? datos.get(clave) : null),
    setItem: (clave, valor) => datos.set(clave, String(valor)),
    removeItem: (clave) => datos.delete(clave),
    datos,
  };
}

function respuesta(status, cuerpo) {
  return { ok: status >= 200 && status < 300, status, json: async () => cuerpo };
}

const SOLICITUD = {
  referencia: "abcdefghjkmnpqrstuvw",
  situacion: "awaiting_approval",
  pedida_utc: "2026-11-13T06:50:00Z",
  agente: { numero: 1 },
  queria: { texto: "\"borrar_archivo\"" },
  sobre: { texto: "\"informe\"" },
  vale_hasta_utc: "2099-01-01T00:00:00Z",
  parametros: [{ clave: "\"nota\"", valor: "\"texto\"" }],
  parametros_visibles: true,
  puede_aprobar: true,
  puede_rechazar: true,
  puede_ejecutar: false,
};

let vez = 0;

// Loads app.js afresh on a new page; returns the page and the requests made.
async function abrirPagina({ guardado, navegador = ["es-CL"], esperas = {} }) {
  const pedidos = [];
  const document = documentoDePagina();
  const local = almacen(guardado ? { praetore_idioma: guardado } : {});
  const globales = {
    document,
    sessionStorage: almacen({ praetore_sesion: "f".repeat(64) }),
    localStorage: local,
    navigator: { languages: navegador },
    window: { location: { hash: "", pathname: "/", search: "" } },
    history: { replaceState() {} },
    FormData: class {
      entries() {
        return [][Symbol.iterator]();
      }
    },
    fetch: async (url, opciones = {}) => {
      const metodo = opciones.method || "GET";
      pedidos.push({ metodo, url, cabeceras: opciones.headers || {} });
      const catalogo = /^\/i18n\/(es|en|pt)\.json$/.exec(url);
      if (catalogo) {
        if (esperas[catalogo[1]]) await esperas[catalogo[1]];
        return respuesta(200, catalogos[catalogo[1]]);
      }
      if (url.startsWith("/api/historial")) {
        return respuesta(200, { pagina: 1, paginas: 1, total: 0, recibos: [], aviso: "receipt_not_authorization" });
      }
      if (url === "/api/bandeja") {
        return respuesta(200, {
          aviso: "inbox_how_it_works",
          solicitudes: [SOLICITUD],
          vencidas: 0,
          ilegibles: 0,
          hay_mas: false,
          limite: 200,
        });
      }
      if (url === "/api/paquete/estado") return respuesta(200, { configurado: true });
      const accion = /^\/api\/bandeja\/[a-z]+\/(aprobar|rechazar|ejecutar)$/.exec(url);
      if (accion && metodo === "POST") {
        const situacion = { aprobar: "approved_pending_execution", rechazar: "rejected", ejecutar: "approved" }[accion[1]];
        const mensaje = { aprobar: "approved_not_yet_executed", rechazar: "rejected_final", ejecutar: "executed" }[accion[1]];
        return respuesta(200, { situacion, mensaje: { codigo: mensaje }, puede_ejecutar: accion[1] === "aprobar" });
      }
      return respuesta(404, {});
    },
  };
  for (const [nombre, valor] of Object.entries(globales)) {
    Object.defineProperty(globalThis, nombre, { value: valor, configurable: true, writable: true });
  }
  vez += 1;
  await import(new URL("app.js?vez=" + vez, raiz).href);
  await calma();
  return { document, pedidos, local };
}

async function calma() {
  for (let i = 0; i < 20; i += 1) await new Promise((listo) => setTimeout(listo, 0));
}

function tarjeta(document) {
  const lista = document.getElementById("solicitudes");
  assert.equal(lista.hijos.length, 1);
  return lista.hijos[0];
}

function botones(nodo) {
  return nodo.querySelectorAll("button").map((boton) => boton.textContent);
}

function botonQueDice(nodo, palabras) {
  const boton = nodo.querySelectorAll("button").find((cada) => cada.textContent === palabras);
  assert.ok(boton, "no button says " + palabras + " in " + JSON.stringify(botones(nodo)));
  return boton;
}

function acciones(pedidos) {
  return pedidos.filter((pedido) => pedido.metodo === "POST").map((pedido) => pedido.url.split("/").pop());
}

for (const idioma of ["es", "en", "pt"]) {
  test(idioma + ": reject asks first, says it is final, and posts to the reject route", async () => {
    const t = catalogos[idioma];
    const { document, pedidos } = await abrirPagina({ guardado: idioma });
    assert.equal(document.documentElement.getAttribute("lang"), idioma === "pt" ? "pt-BR" : idioma);
    assert.equal(document.getElementById("idioma").value, idioma);
    const caja = tarjeta(document);
    assert.deepEqual(botones(caja), [t["button.approve_execute"], t["button.reject"]]);
    botonQueDice(caja, t["button.reject"]).click();
    await calma();
    assert.deepEqual(acciones(pedidos), [], "the first click only asks");
    const pregunta = caja.querySelectorAll("strong").map((nodo) => nodo.textContent);
    assert.ok(pregunta.includes(t["confirm.reject.question"]), JSON.stringify(pregunta));
    assert.match(t["confirm.reject.question"].toLowerCase(), idioma === "es" ? /es final/ : /final/);
    botonQueDice(caja, t["confirm.reject.button"]).click();
    await calma();
    assert.deepEqual(acciones(pedidos), ["rechazar"]);
    assert.ok(caja.textContent.includes(t["situation.rejected"]));
    assert.ok(caja.textContent.includes(t["message.rejected_final"]));
    // No request says the language.
    for (const pedido of pedidos) {
      const nombres = Object.keys(pedido.cabeceras).map((nombre) => nombre.toLowerCase());
      assert.ok(!nombres.includes("accept-language"), pedido.url);
      assert.ok(!pedido.url.includes("idioma"), pedido.url);
    }
  });

  test(idioma + ": approve and execute post to approve, then execute", async () => {
    const t = catalogos[idioma];
    const { document, pedidos } = await abrirPagina({ guardado: idioma });
    const caja = tarjeta(document);
    botonQueDice(caja, t["button.approve_execute"]).click();
    await calma();
    const pregunta = caja.querySelectorAll("strong").map((nodo) => nodo.textContent);
    assert.ok(pregunta.includes(t["confirm.approve_execute.question"]));
    botonQueDice(caja, t["confirm.approve_execute.button"]).click();
    await calma();
    assert.deepEqual(acciones(pedidos), ["aprobar", "ejecutar"]);
  });
}

test("a change of language with a confirmation open cancels it, and nothing is sent", async () => {
  const { document, pedidos, local } = await abrirPagina({ guardado: null, navegador: ["es-CL"] });
  const caja = tarjeta(document);
  botonQueDice(caja, catalogos.es["button.reject"]).click();
  await calma();
  assert.ok(botones(caja).includes(catalogos.es["confirm.reject.button"]));
  const selector = document.getElementById("idioma");
  selector.value = "en";
  selector.disparar("change");
  await calma();
  assert.equal(local.datos.get("praetore_idioma"), "en");
  assert.equal(document.documentElement.getAttribute("lang"), "en");
  // Back to the decision buttons, in English; the summary is gone.
  assert.deepEqual(botones(caja), [catalogos.en["button.approve_execute"], catalogos.en["button.reject"]]);
  assert.ok(!caja.textContent.includes(catalogos.es["confirm.reject.question"]));
  assert.ok(!caja.textContent.includes(catalogos.en["confirm.reject.question"]));
  assert.deepEqual(acciones(pedidos), []);
  // The static texts follow the language.
  const titulo = document.querySelectorAll("[data-i18n]").find((nodo) => nodo.getAttribute("data-i18n") === "inbox.title");
  assert.equal(titulo.textContent, catalogos.en["inbox.title"]);
});

test("two quick changes of language: the page and the selector end in the last one", async () => {
  let soltarIngles;
  const esperas = { en: new Promise((listo) => (soltarIngles = listo)) };
  const { document, local } = await abrirPagina({ guardado: "es", esperas });
  const selector = document.getElementById("idioma");
  selector.value = "en";
  selector.disparar("change");
  selector.value = "pt";
  selector.disparar("change");
  await calma();
  // The English catalog arrives after the Portuguese one, and is ignored.
  soltarIngles();
  await calma();
  assert.equal(selector.value, "pt");
  assert.equal(local.datos.get("praetore_idioma"), "pt");
  assert.equal(document.documentElement.getAttribute("lang"), "pt-BR");
  const titulo = document.querySelectorAll("[data-i18n]").find((nodo) => nodo.getAttribute("data-i18n") === "inbox.title");
  assert.equal(titulo.textContent, catalogos.pt["inbox.title"]);
  assert.ok(tarjeta(document).textContent.includes(catalogos.pt["button.reject"]));
});

test("the language comes from the browser when nothing is saved, and an unknown saved value is ignored", async () => {
  let pagina = await abrirPagina({ guardado: null, navegador: ["pt-PT", "en"] });
  assert.equal(pagina.document.documentElement.getAttribute("lang"), "pt-BR");
  pagina = await abrirPagina({ guardado: "xx", navegador: ["de-DE", "en-GB"] });
  assert.equal(pagina.document.documentElement.getAttribute("lang"), "en");
  pagina = await abrirPagina({ guardado: "xx", navegador: ["de-DE"] });
  assert.equal(pagina.document.documentElement.getAttribute("lang"), "es");
  assert.deepEqual(
    pagina.pedidos.filter((pedido) => pedido.url.startsWith("/i18n/")).map((pedido) => pedido.url),
    ["/i18n/es.json"],
  );
});

test("the card shows its deadline in local time with its offset and in UTC, with seconds", async () => {
  const { document } = await abrirPagina({ guardado: "en" });
  const caja = tarjeta(document);
  assert.match(caja.textContent, /\(UTC[+-]\d\d:\d\d\) · 2099-01-01 00:00:00 UTC/);
  assert.match(caja.textContent, /\(UTC[+-]\d\d:\d\d\) · 2026-11-13 06:50 UTC/);
  assert.ok(caja.textContent.includes(catalogos.en["agent.numbered"].replace("{numero}", "1")));
});
